using System.Globalization;
using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Authorization;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace FronteggAuth.Samples.Api.Endpoints;

/// <summary>
/// Endpoints that answer "why was I denied?". Useful while wiring a new host up against a real tenant; none of
/// this belongs in a production API, which is why every one of them is grouped under <c>/api/diagnostics</c>.
/// </summary>
public static class DiagnosticsEndpoints
{
    /// <summary>Maps the diagnostic endpoints onto <paramref name="app"/>.</summary>
    public static IEndpointRouteBuilder MapDiagnosticsEndpoints(this IEndpointRouteBuilder app)
    {
        // The one genuinely public endpoint. AllowAnonymous is required, not optional: the package's gating
        // middleware runs before authorization and rejects any matched endpoint that does not carry it, so
        // "I attached no policy" is not the same as "this is public".
        app.MapGet("/api/ping", () => new PingResponse("ok"))
            .AllowAnonymous()
            .WithName("Ping");

        var diagnostics = app.MapGroup("/api/diagnostics");

        // What the package made of the credential. GetUserAsync rather than the User property: User projects
        // only what is already on the principal, while GetUserAsync back-fills roles and permissions from the
        // claims provider when the enrichment middleware was skipped for this request.
        diagnostics.MapGet("/me", async (
            HttpContext httpContext,
            IIdentityUserService identityUserService,
            IOptions<FronteggSettings> settings,
            CancellationToken cancellationToken) =>
        {
            var user = await identityUserService.GetUserAsync(cancellationToken);
            if (user is null) return Results.NotFound();

            var apiKeyHeader = settings.Value.ApiKeyHeaderName;

            return Results.Ok(new MeResponse(
                Id: user.Id,
                Email: user.Email,
                FullName: user.FullName,
                CompanyId: user.CompanyId,
                CompanyName: user.CompanyName,
                IsAdmin: user.IsAdmin,
                IsSystemUser: user.IsSystemUser,
                Roles: user.Roles,
                Permissions: user.Permissions,
                PermissionIds: user.PermissionIds,
                Credential: new CredentialInfo(
                    // Which handler ran. Frontegg.ApiKey means the X-API-KEY path (lifetime ignored, revocation
                    // checked against Frontegg); Bearer means an ordinary access token.
                    Scheme: httpContext.User.Identity?.AuthenticationType,
                    UsedApiKeyHeader: httpContext.Request.Headers.ContainsKey(apiKeyHeader),
                    UsedAuthorizationHeader: httpContext.Request.Headers.ContainsKey("Authorization"))));
        }).WithName("Me");

        // The same data one layer down. When a field on /me is empty but the claim is present here, the mismatch
        // is a claim-type mapping problem — override the name under FronteggSettings:ClaimTypeNames.
        diagnostics.MapGet("/claims", (ClaimsPrincipal principal) =>
            new ClaimsResponse(
                principal.Identity?.AuthenticationType,
                [.. Displayable(principal.Claims).Select(claim => new ClaimDto(claim.Type, claim.Value))]))
            .WithName("Claims");

        // Evaluates a policy without being gated by it, so a 200 body can say "denied" and you can tell an
        // authorization failure apart from a routing or authentication one.
        diagnostics.MapGet("/permission", async (
            string key,
            ClaimsPrincipal principal,
            IAuthorizationService authorizationService) =>
        {
            var policy = FronteggPolicyProvider.PermissionPrefix + key;
            var result = await authorizationService.AuthorizeAsync(principal, resource: null, policy);

            return new PolicyProbeResponse(policy, result.Succeeded);
        }).WithName("ProbePermission");

        diagnostics.MapGet("/permission-id/{id:int}", async (
            int id,
            ClaimsPrincipal principal,
            IAuthorizationService authorizationService,
            IOptions<FronteggSettings> settings) =>
        {
            var policy = FronteggPolicyProvider.PermissionIdPrefix + id.ToString(CultureInfo.InvariantCulture);
            var result = await authorizationService.AuthorizeAsync(principal, resource: null, policy);

            // The id map is the usual culprit for an unexpected denial: with no mapping for this id the numeric
            // claim is never emitted, and the denial is indistinguishable from a genuinely missing permission.
            string? mappedKey = null;
            settings.Value.PermissionIdMappings?.TryGetValue(id, out mappedKey);

            return new PermissionIdProbeResponse(policy, result.Succeeded, mappedKey);
        }).WithName("ProbePermissionId");

        // Pre-flight for the tenant (client-credentials) token: proves FronteggSettings:TenantClientId and
        // :TenantSecret are usable. The token itself is a live credential and is never returned.
        diagnostics.MapGet("/tenant-token", async (
            IFronteggAccountTokenService accountTokenService,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var token = await accountTokenService.GetTenantTokenAsync(cancellationToken);
                return Results.Ok(new TenantTokenResponse(Acquired: !string.IsNullOrEmpty(token), Error: null));
            }
            catch (HttpRequestException exception)
            {
                // Logged without the response body: a failed token exchange can echo the client secret back.
                loggerFactory.CreateLogger("TenantToken").LogWarning("Tenant token exchange failed with {Status}.", exception.StatusCode);
                return Results.Ok(new TenantTokenResponse(Acquired: false, Error: exception.StatusCode?.ToString()));
            }
        }).WithName("TenantToken");

        return app;
    }

    // access_token, id_token and refresh_token arrive as ordinary claims. Echoing them from a diagnostic
    // endpoint would hand a caller a credential it did not already have in a form that lands in logs and
    // proxy caches.
    private static IEnumerable<Claim> Displayable(IEnumerable<Claim> claims) =>
        claims.Where(claim => claim.Type is not ("access_token" or "id_token" or "refresh_token"));

    private sealed record PingResponse(string Status);

    private sealed record CredentialInfo(string? Scheme, bool UsedApiKeyHeader, bool UsedAuthorizationHeader);

    private sealed record MeResponse(
        Guid Id,
        string? Email,
        string FullName,
        int CompanyId,
        string? CompanyName,
        bool IsAdmin,
        bool IsSystemUser,
        IReadOnlyList<string> Roles,
        IReadOnlyList<string> Permissions,
        IReadOnlyList<int> PermissionIds,
        CredentialInfo Credential);

    private sealed record ClaimDto(string Type, string Value);

    private sealed record ClaimsResponse(string? Scheme, IReadOnlyList<ClaimDto> Claims);

    private sealed record PolicyProbeResponse(string Policy, bool Granted);

    private sealed record PermissionIdProbeResponse(string Policy, bool Granted, string? MapsToKey);

    private sealed record TenantTokenResponse(bool Acquired, string? Error);
}
