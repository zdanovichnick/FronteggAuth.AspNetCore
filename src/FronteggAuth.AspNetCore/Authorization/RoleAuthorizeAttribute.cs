using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Authorizes an action/controller when the user is in <em>any</em> of <see cref="AllowedRoles"/>.
/// Example: <c>[RoleAuthorize("admin", "editor")]</c>.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RoleAuthorizeAttribute : Attribute, IAuthorizationFilter
{
    /// <summary>Roles, any of which grants access.</summary>
    public string[] AllowedRoles { get; }

    /// <summary>Creates the attribute requiring any of the given roles.</summary>
    public RoleAuthorizeAttribute(params string[] allowedRoles) => AllowedRoles = allowedRoles;

    /// <inheritdoc />
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (AuthorizationFilterGuards.ShouldSkip(context))
            return;

        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (AllowedRoles.Length > 0 && !AllowedRoles.Any(user.IsInRole))
            context.Result = AuthorizationFilterGuards.Forbidden("Missing required role.");
    }
}
