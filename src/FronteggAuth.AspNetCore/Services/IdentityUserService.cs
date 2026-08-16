using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>Builds an <see cref="ApplicationUser"/> from the request principal and resolves the current access token.</summary>
public sealed class IdentityUserService(
    IHttpContextAccessor httpContextAccessor,
    IUserClaimsProvider claimsProvider,
    IOptions<FronteggSettings> options,
    ILogger<IdentityUserService> logger) : IIdentityUserService
{
    private readonly FronteggClaimTypeOptions _claims = options.Value.ClaimTypeNames;
    private readonly string _apiKeyHeader = options.Value.ApiKeyHeaderName;
    private ApplicationUser? _user;
    private bool _enrichmentAttempted;

    private HttpContext? Context => httpContextAccessor.HttpContext;

    /// <inheritdoc />
    public ApplicationUser? User
    {
        get
        {
            var context = Context;
            if (context?.User.Identity?.IsAuthenticated != true)
                return null;

            if (_user is not null)
                return _user;

            var claims = context.User.Claims.ToList();

            var userIdValue = ClaimHelper.GetUserId(claims, _claims.UserId);
            var userId = Guid.TryParse(userIdValue, out var parsed) ? parsed : Guid.Empty;
            var companyId = int.TryParse(ClaimHelper.GetCompanyId(claims, _claims.TenantId), out var parsedCompanyId)
                    ? parsedCompanyId : 0;

            var companyName = ClaimHelper.GetMetadataValue(claims, "accountName")
                ?? GetClaim(claims, _claims.CompanyName);

            var company = new CompanyInfo(
                companyId,
                companyName,
                GetClaim(claims, _claims.Department));

            var vendorMetadata = ClaimHelper.GetVendorMetadata(claims);

            var permissions = new PermissionSet(
                ClaimHelper.GetPermissionKeys(claims, _claims.Permissions),
                ClaimHelper.GetPermissionIds(claims, _claims.PermissionIds));

            var roles = ClaimHelper.GetRoleKeys(claims, _claims.Role);

            _user = new ApplicationUser(
                userId,
                GetClaim(claims, _claims.Name) ?? GetClaim(claims, ClaimTypes.Name),
                GetClaim(claims, _claims.FirstName),
                GetClaim(claims, _claims.LastName),
                company,
                GetClaim(claims, _claims.Email) ?? GetClaim(claims, ClaimTypes.Email),
                permissions,
                isAdmin: roles.Any(r => r.Equals("admin", StringComparison.OrdinalIgnoreCase)),
                isSystemUser: roles.Any(r => r.Equals("system", StringComparison.OrdinalIgnoreCase) || r.Equals("api", StringComparison.OrdinalIgnoreCase)),
                GetClaim(claims, _claims.ProfilePictureUrl),
                roles,
                vendorMetadata);

            return _user;
        }
    }

    /// <inheritdoc />
    public async Task<ApplicationUser?> GetUserAsync(CancellationToken cancellationToken = default)
    {
        var user = User;
        if (user is null || _enrichmentAttempted)
            return user;

        // Enriched only when every claims-provider-sourced field is present — a principal that already has a
        // company name but arrived without permissions (e.g. UpdateClaimsMiddleware was skipped for this
        // request) must still trigger a fetch, not be mistaken for already enriched. Numeric permission IDs are
        // deliberately not part of the test: they only exist when PermissionIdMappings is configured, so
        // requiring them would make every request of an application that addresses permissions by key alone
        // look unenriched and pay a round-trip.
        var alreadyEnriched = !string.IsNullOrWhiteSpace(user.CompanyName)
            && user.Permissions.Count > 0;
        if (alreadyEnriched)
            return user;

        if (Context?.User.Identity is not ClaimsIdentity identity)
            return user;

        // One attempt per request regardless of outcome: a tenant/user may legitimately have no company name
        // or no permissions, and re-fetching on every call would turn that into an HTTP round-trip per access.
        _enrichmentAttempted = true;

        var userId = ClaimHelper.GetUserId(identity.Claims, _claims.UserId);
        var companyId = ClaimHelper.GetCompanyId(identity.Claims, _claims.TenantId);
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(companyId))
            return user;

        List<Claim> fetched;
        try
        {
            fetched = await claimsProvider.GetUserClaimsAsync(userId, companyId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Fails open, unlike the claims-enrichment middleware: this runs after authorization has already been
            // decided, so an unenriched projection cannot widen access — it only omits display values.
            logger.LogWarning(ex, "Could not enrich claims on demand for user {UserId} tenant {TenantId}", userId, companyId);
            return user;
        }

        ClaimHelper.AddUniqueClaims(identity, fetched);

        // Drop the projection cached from the pre-enrichment claim set so the next read rebuilds from the merged one.
        _user = null;
        return User;
    }

    /// <inheritdoc />
    public async Task<string?> GetCurrentUserTokenAsync(CancellationToken cancellationToken = default)
    {
        var context = Context;
        if (context is null)
            return null;

        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return authHeader["Bearer ".Length..].Trim();

        var apiKey = context.Request.Headers[_apiKeyHeader].ToString();
        if (!string.IsNullOrWhiteSpace(apiKey))
            return apiKey;

        // HttpContext.GetTokenAsync has no cancellation-aware overload; the parameter exists for interface
        // consistency with every other method on IIdentityUserService.
        return await context.GetTokenAsync(_claims.AccessToken);
    }

    private static string? GetClaim(IList<Claim> claims, string type)
    {
        var value = claims.FirstOrDefault(c => c.Type.Equals(type, StringComparison.OrdinalIgnoreCase))?.Value;
        if (!string.IsNullOrWhiteSpace(value))
            return value;

        value = ClaimHelper.GetCustomClaimValue(claims, type);
        return !string.IsNullOrWhiteSpace(value) ? value : null;
    }
}
