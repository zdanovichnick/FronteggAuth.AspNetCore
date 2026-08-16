using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Authorizes an action/controller against numeric permission IDs. Access is granted when the user
/// holds <em>any</em> of <see cref="Permissions"/> and holds <em>none</em> of <see cref="ReversePermissions"/>.
/// Example: <c>[PermissionIdAuthorize(123)]</c>.
/// Numeric IDs are only populated when a permission-id map/resolver is configured.
/// A principal holding a role listed in <see cref="FronteggSettings.BypassRoles"/> (<c>system</c> by default) —
/// or one whose token type is listed in
/// <see cref="FronteggSettings.BypassTokenTypes"/> (<c>tenantApiToken</c> by default) — bypasses the permission
/// checks entirely.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class PermissionIdAuthorizeAttribute : Attribute, IAuthorizationFilter
{
    /// <summary>Permission IDs, any of which grants access.</summary>
    public int[] Permissions { get; set; } = [];

    /// <summary>Permission IDs, any of which denies access.</summary>
    public int[] ReversePermissions { get; set; } = [];

    /// <summary>Creates the attribute requiring any of the given numeric permission IDs.</summary>
    public PermissionIdAuthorizeAttribute(params int[] permissions) => Permissions = permissions;

    /// <inheritdoc />
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (AuthorizationFilterGuards.ShouldSkip(context))
            return;

        var denied = AuthorizationFilterGuards.CheckCommon(context);
        if (denied is not null)
        {
            context.Result = denied;
            return;
        }

        var settings = context.HttpContext.RequestServices.GetRequiredService<IOptions<FronteggSettings>>().Value;

        if (PermissionBypass.Applies(context.HttpContext.User, settings))
            return;

        var userPermissions = ClaimHelper.GetPermissionIds(
            context.HttpContext.User.Claims, settings.ClaimTypeNames.PermissionIds);

        if (ReversePermissions.Length > 0 && ReversePermissions.Any(userPermissions.Contains))
        {
            context.Result = AuthorizationFilterGuards.Forbidden("Access denied by reverse permission.");
            return;
        }

        if (Permissions.Length > 0 && !Permissions.Any(userPermissions.Contains))
        {
            context.Result = AuthorizationFilterGuards.Forbidden("Missing required permission.");
        }
    }
}
