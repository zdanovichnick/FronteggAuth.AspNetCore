using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Grants <see cref="PermissionRequirement"/> when the principal holds the required Frontegg permission key,
/// or when <see cref="PermissionBypass"/> applies.
/// </summary>
internal sealed class PermissionAuthorizationHandler(IOptions<FronteggSettings> options)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var settings = options.Value;

        if (PermissionBypass.Applies(context.User, settings))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var permissions = ClaimHelper.GetPermissionKeys(context.User.Claims, settings.ClaimTypeNames.Permissions);

        if (permissions.Contains(requirement.Permission, StringComparer.OrdinalIgnoreCase))
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}

/// <summary>
/// Grants <see cref="PermissionIdRequirement"/> when the principal holds the required numeric permission ID,
/// or when <see cref="PermissionBypass"/> applies.
/// </summary>
internal sealed class PermissionIdAuthorizationHandler(IOptions<FronteggSettings> options)
    : AuthorizationHandler<PermissionIdRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionIdRequirement requirement)
    {
        var settings = options.Value;

        if (PermissionBypass.Applies(context.User, settings))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var permissions = ClaimHelper.GetPermissionIds(context.User.Claims, settings.ClaimTypeNames.PermissionIds);

        if (permissions.Contains(requirement.PermissionId))
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
