using System.Security.Claims;
using FronteggAuth.AspNetCore.Authorization;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Models;
using AwesomeAssertions;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class PermissionBypassTests
{
    [Fact]
    public void Applies_SystemRole_ReturnsTrue()
    {
        var user = PrincipalWith(new Claim(ClaimTypes.Role, FronteggRoles.System));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("SYSTEM")]
    [InlineData("System")]
    public void Applies_SystemRoleDifferingInCase_ReturnsTrue(string role)
    {
        var user = PrincipalWith(new Claim(ClaimTypes.Role, role));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeTrue();
    }

    // The configuration binder builds a case-sensitive HashSet, so the comparison has to be explicit at the
    // call site rather than inherited from the default set's comparer.
    [Fact]
    public void Applies_CaseSensitiveBypassRoleSetFromConfiguration_StillMatches()
    {
        var settings = new FronteggSettings
        {
            BypassRoles = new HashSet<string> { "platformOperator" }
        };
        var user = PrincipalWith(new Claim(ClaimTypes.Role, "PlatformOperator"));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeTrue();
    }

    [Fact]
    public void Applies_BypassRolesCleared_SystemRoleNoLongerBypasses()
    {
        var settings = new FronteggSettings();
        settings.BypassRoles.Clear();
        var user = PrincipalWith(new Claim(ClaimTypes.Role, FronteggRoles.System));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeFalse();
    }

    [Fact]
    public void Applies_RenamedRoleClaim_IsHonoured()
    {
        var settings = new FronteggSettings();
        settings.ClaimTypeNames.Role = "roles";
        var user = PrincipalWith(new Claim("roles", FronteggRoles.System));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeTrue();
    }

    [Fact]
    public void Applies_RoleNotListed_ReturnsFalse()
    {
        var user = PrincipalWith(new Claim(ClaimTypes.Role, FronteggRoles.Admin));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeFalse();
    }

    [Fact]
    public void Applies_TenantApiTokenType_ReturnsTrue()
    {
        var user = PrincipalWith(new Claim("type", FronteggTokenTypes.TenantApiToken));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("TENANTAPITOKEN")]
    [InlineData("tenantapitoken")]
    public void Applies_TokenTypeDifferingInCase_ReturnsTrue(string tokenType)
    {
        var user = PrincipalWith(new Claim("type", tokenType));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeTrue();
    }

    [Fact]
    public void Applies_CaseSensitiveBypassSetFromConfiguration_StillMatches()
    {
        var settings = new FronteggSettings
        {
            BypassTokenTypes = new HashSet<string> { FronteggTokenTypes.TenantApiToken }
        };
        var user = PrincipalWith(new Claim("type", "TenantApiToken"));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeTrue();
    }

    [Fact]
    public void Applies_TokenTypeNotListed_ReturnsFalse()
    {
        var user = PrincipalWith(new Claim("type", "userToken"));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeFalse();
    }

    [Fact]
    public void Applies_BypassTokenTypesCleared_ReturnsFalse()
    {
        var settings = new FronteggSettings();
        settings.BypassTokenTypes.Clear();
        var user = PrincipalWith(new Claim("type", FronteggTokenTypes.TenantApiToken));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeFalse();
    }

    [Fact]
    public void Applies_NoTokenTypeClaim_ReturnsFalse()
    {
        var user = PrincipalWith(new Claim("permissions", "fe.read"));

        var result = PermissionBypass.Applies(user, new FronteggSettings());

        result.Should().BeFalse();
    }

    [Fact]
    public void Applies_RenamedTokenTypeClaim_IsHonoured()
    {
        var settings = new FronteggSettings();
        settings.ClaimTypeNames.TokenType = "token_type";
        var user = PrincipalWith(new Claim("token_type", FronteggTokenTypes.TenantApiToken));

        var result = PermissionBypass.Applies(user, settings);

        result.Should().BeTrue();
    }

    private static ClaimsPrincipal PrincipalWith(params Claim[] claims)
        => new(new ClaimsIdentity(claims, "test"));
}
