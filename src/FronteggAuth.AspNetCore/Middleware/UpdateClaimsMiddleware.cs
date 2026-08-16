using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace FronteggAuth.AspNetCore.Middleware;

/// <summary>
/// Enriches the authenticated principal with permission/role claims from <see cref="IUserClaimsProvider"/>,
/// applies the optional <see cref="IClaimsTransformer"/>, and enforces <see cref="IAccountStatusValidator"/>.
/// On a failed status check it signs out cookie sessions and returns 401 with an <c>X-Force-Logout</c> header.
/// </summary>
public sealed class UpdateClaimsMiddleware(RequestDelegate next, ILogger<UpdateClaimsMiddleware> logger)
{
    /// <summary>Enriches the principal and enforces account status for the current request.</summary>
    public async Task InvokeAsync(
        HttpContext context,
        IUserClaimsProvider claimsProvider,
        IAccountStatusValidator statusValidator,
        IClaimsTransformer claimsTransformer,
        IOptions<FronteggSettings> options)
    {
        var path = context.Request.Path;
        if (path.StartsWithSegments("/signin-oidc") || path.StartsWithSegments("/signout-callback-oidc")
            || context.User.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
        {
            await next(context);
            return;
        }

        if (context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var claimNames = options.Value.ClaimTypeNames;

        var userId = ClaimHelper.GetUserId(identity.Claims, claimNames.UserId);
        var companyId = ClaimHelper.GetCompanyId(identity.Claims, claimNames.TenantId);
        var tokenType = ClaimHelper.GetTokenType(identity.Claims, claimNames.TokenType);

        if (!string.IsNullOrEmpty(userId) && !string.IsNullOrEmpty(companyId) && FronteggTokenTypes.TenantApiToken != tokenType)
        {
            try
            {
                var claims = await claimsProvider.GetUserClaimsAsync(userId, companyId, context.RequestAborted);
                ClaimHelper.AddUniqueClaims(identity, claims);
                claimsTransformer.Transform(identity);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to enrich claims for user {UserId} tenant {TenantId}", userId, companyId);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }
        else
        {
            if (string.IsNullOrEmpty(companyId))
            {
                var redactedClaimTypes = new[] { claimNames.AccessToken, claimNames.IdToken };
                var claimsSummary = string.Join(", ", identity.Claims.Select(claim =>
                    $"{claim.Type}={(redactedClaimTypes.Contains(claim.Type, StringComparer.OrdinalIgnoreCase) ? "[redacted]" : claim.Value)}"));

                logger.LogWarning(
                    "Authenticated principal missing user/tenant claims (user={UserId} tenant={TenantId} path={Path} claims={Claims})",
                    userId ?? "(null)", companyId ?? "(null)", path, claimsSummary);
            }
        }

        if (!statusValidator.HasAccess(identity.Claims.ToList()))
        {
            var isTokenRequest = context.Request.Headers.ContainsKey(options.Value.ApiKeyHeaderName)
                || (context.Request.Headers.Authorization.FirstOrDefault()?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ?? false);

            if (!isTokenRequest)
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.Append("X-Force-Logout", "true");
            return;
        }

        await next(context);
    }
}
