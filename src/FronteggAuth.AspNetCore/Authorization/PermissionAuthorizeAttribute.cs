using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Authorizes an action/controller against native Frontegg permission keys. Access is granted when the user
/// holds <em>any</em> of <see cref="Permissions"/> and holds <em>none</em> of <see cref="ReversePermissions"/>.
/// Pass multiple keys to one attribute for OR semantics: <c>[PermissionAuthorize("fe.secure.read", "fe.secure.write")]</c>.
/// Stack multiple attributes for AND semantics, since <see cref="AttributeUsageAttribute.AllowMultiple"/> is set and
/// each instance is evaluated independently:
/// <c>[PermissionAuthorize("fe.secure.read")] [PermissionAuthorize("fe.secure.write")]</c>.
/// A principal holding a role listed in <see cref="FronteggSettings.BypassRoles"/> (<c>system</c> by default) —
/// or one whose token type is listed in
/// <see cref="FronteggSettings.BypassTokenTypes"/> (<c>tenantApiToken</c> by default) — bypasses the permission
/// checks entirely.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class PermissionAuthorizeAttribute : Attribute, IAuthorizationFilter
{
    /// <summary>Permission keys, any of which grants access.</summary>
    public string[] Permissions { get; set; } = [];

    /// <summary>Permission keys, any of which denies access.</summary>
    public string[] ReversePermissions { get; set; } = [];

    /// <summary>Creates the attribute requiring any of the given permission keys.</summary>
    public PermissionAuthorizeAttribute(params string[] permissions) => Permissions = permissions;

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

        var settings = context.HttpContext.RequestServices
            .GetRequiredService<IOptions<FronteggSettings>>().Value;

        if (PermissionBypass.Applies(context.HttpContext.User, settings))
            return;

        var userPermissions = ClaimHelper.GetPermissionKeys(
            context.HttpContext.User.Claims, settings.ClaimTypeNames.Permissions);

        if (ReversePermissions.Length > 0 &&
            ReversePermissions.Any(p => userPermissions.Contains(p, StringComparer.OrdinalIgnoreCase)))
        {
            context.Result = AuthorizationFilterGuards.Forbidden("Access denied by reverse permission.");
            return;
        }

        if (Permissions.Length > 0 &&
            !Permissions.Any(p => userPermissions.Contains(p, StringComparer.OrdinalIgnoreCase)))
        {
            context.Result = AuthorizationFilterGuards.Forbidden("Missing required permission.");
        }
    }
}
