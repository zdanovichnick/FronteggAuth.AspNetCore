using System.Security.Claims;
using FronteggAuth.AspNetCore.Authorization;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Models;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class AuthorizationHandlerTests
{
    [Fact]
    public async Task PermissionHandler_UserHasPermission_Succeeds()
    {
        var handler = new PermissionAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionRequirement("fe.read");
        var context = ContextWith(requirement, new Claim("permissions", "fe.read,fe.write"));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task PermissionHandler_UserLacksPermission_DoesNotSucceed()
    {
        var handler = new PermissionAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionRequirement("fe.delete");
        var context = ContextWith(requirement, new Claim("permissions", "fe.read"));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
    }

    [Fact]
    public async Task PermissionHandler_TenantApiTokenPrincipal_SucceedsWithoutPermissionClaim()
    {
        var handler = new PermissionAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionRequirement("fe.delete");
        var context = ContextWith(requirement, new Claim("type", FronteggTokenTypes.TenantApiToken));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task PermissionHandler_SystemRolePrincipal_SucceedsWithoutPermissionClaim()
    {
        var handler = new PermissionAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionRequirement("fe.delete");
        var context = ContextWith(requirement, new Claim(ClaimTypes.Role, FronteggRoles.System));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task PermissionIdHandler_UserHasId_Succeeds()
    {
        var handler = new PermissionIdAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionIdRequirement(123);
        var context = ContextWith(requirement, new Claim("Permission", "123,124"));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeTrue();
    }

    [Fact]
    public async Task PermissionIdHandler_UserLacksId_DoesNotSucceed()
    {
        var handler = new PermissionIdAuthorizationHandler(Options.Create(new FronteggSettings()));
        var requirement = new PermissionIdRequirement(999);
        var context = ContextWith(requirement, new Claim("Permission", "123"));

        await handler.HandleAsync(context);

        context.HasSucceeded.Should().BeFalse();
    }

    private static AuthorizationHandlerContext ContextWith(IAuthorizationRequirement requirement, params Claim[] claims)
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
        return new AuthorizationHandlerContext([requirement], user, resource: null);
    }
}
