using System.Security.Claims;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// The unconditional-access rule shared by the permission attributes and the permission authorization handlers,
/// so an attribute-protected endpoint and its policy equivalent always agree.
/// </summary>
internal static class PermissionBypass
{
    /// <summary>
    /// Whether the principal is granted access without holding any specific permission: it holds one of
    /// <see cref="FronteggSettings.BypassRoles"/>, or its token type is listed in
    /// <see cref="FronteggSettings.BypassTokenTypes"/>.
    /// </summary>
    public static bool Applies(ClaimsPrincipal user, FronteggSettings settings)
    {
        var claimNames = settings.ClaimTypeNames;

        // Roles are read through ClaimHelper rather than ClaimsPrincipal.IsInRole: IsInRole compares role
        // *values* ordinally, so a tenant whose catalog spells the role "System" would miss a bypass configured
        // as "system". Both comparisons below are explicitly case-insensitive for the same reason: a set bound
        // from configuration is a default (case-sensitive) HashSet, not the OrdinalIgnoreCase one declared here.
        var bypassRoles = settings.BypassRoles;
        if (bypassRoles is { Count: > 0 })
        {
            var roles = ClaimHelper.GetRoleKeys(user.Claims, claimNames.Role);
            if (roles.Any(role => bypassRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                return true;
        }

        var bypassTokenTypes = settings.BypassTokenTypes;
        if (bypassTokenTypes is not { Count: > 0 })
            return false;

        var tokenType = ClaimHelper.GetTokenType(user.Claims, claimNames.TokenType);

        return !string.IsNullOrEmpty(tokenType) && bypassTokenTypes.Contains(tokenType, StringComparer.OrdinalIgnoreCase);
    }
}
