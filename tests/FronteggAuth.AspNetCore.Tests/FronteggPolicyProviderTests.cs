using FronteggAuth.AspNetCore.Authorization;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggPolicyProviderTests
{
    [Fact]
    public async Task GetPolicyAsync_PermPrefix_BuildsPermissionRequirement()
    {
        var policy = await CreateProvider().GetPolicyAsync("perm:fe.read");

        policy.Should().NotBeNull();
        policy!.Requirements.OfType<PermissionRequirement>()
            .Should().ContainSingle(r => r.Permission == "fe.read");
    }

    [Fact]
    public async Task GetPolicyAsync_PermissionIdPrefix_BuildsPermissionIdRequirement()
    {
        var policy = await CreateProvider().GetPolicyAsync("permid:123");

        policy.Should().NotBeNull();
        policy!.Requirements.OfType<PermissionIdRequirement>()
            .Should().ContainSingle(r => r.PermissionId == 123);
    }

    [Fact]
    public async Task GetPolicyAsync_UnknownPolicy_FallsBackToNull()
    {
        var policy = await CreateProvider().GetPolicyAsync("some-other-policy");

        policy.Should().BeNull();
    }

    private static FronteggPolicyProvider CreateProvider()
        => new(Options.Create(new AuthorizationOptions()));
}
