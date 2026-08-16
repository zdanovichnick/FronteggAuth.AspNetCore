using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.AspNetCore.Services;
using AwesomeAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

/// <summary>
/// The permissions lookup consuming applications call. It owns no data path — it projects whatever
/// <see cref="IUserClaimsProvider"/> returns, reading the claim-type names from configuration.
/// </summary>
public class UserPermissionsServiceTests
{
    private const string UserId = "user-1";
    private const string CompanyId = "tenant-1";

    [Fact]
    public async Task GetPermissionsAsync_ProjectsPermissionKeysIdsAndRoles()
    {
        var provider = NewProvider(
            new Claim("permissions", "fe.secure.read,fe.secure.write"),
            new Claim("Permission", "123,456"),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "editor"));

        var result = await CreateSut(provider).GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        result.Permissions.Should().Equal("fe.secure.read", "fe.secure.write");
        result.PermissionIds.Should().Equal(123, 456);
        result.Roles.Should().Equal("admin", "editor");
    }

    // The whole reason this projection belongs in the package: a host may rename any claim type, so a
    // consuming application must never have to name them itself.
    [Fact]
    public async Task GetPermissionsAsync_WithCustomClaimTypeNames_ReadsConfiguredTypes()
    {
        var provider = NewProvider(
            new Claim("app-perms", "fe.secure.read"),
            new Claim("app-perm-ids", "789"),
            new Claim("app-role", "owner"),
            new Claim("permissions", "should.be.ignored"),
            new Claim("Permission", "999"),
            new Claim(ClaimTypes.Role, "ignored-role"));

        var settings = new FronteggSettings();
        settings.ClaimTypeNames.Permissions = "app-perms";
        settings.ClaimTypeNames.PermissionIds = "app-perm-ids";
        settings.ClaimTypeNames.Role = "app-role";

        var result = await CreateSut(provider, settings).GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        result.Permissions.Should().Equal("fe.secure.read");
        result.PermissionIds.Should().Equal(789);
        result.Roles.Should().Equal("owner");
    }

    [Fact]
    public async Task GetPermissionsAsync_WhenProviderReturnsNoClaims_ReturnsEmptySet()
    {
        var result = await CreateSut(NewProvider()).GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        result.Should().Be(Models.UserPermissions.Empty);
    }

    [Fact]
    public async Task GetPermissionsAsync_WhenOnlyPermissionKeysPresent_LeavesPermissionIdsEmpty()
    {
        var provider = NewProvider(new Claim("permissions", "fe.unmapped.key"));

        var result = await CreateSut(provider).GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        result.Permissions.Should().Equal("fe.unmapped.key");
        result.PermissionIds.Should().BeEmpty();
    }

    // A provider failure must not be flattened into an empty permission set — that reads as "no access"
    // and hides the outage from the caller.
    [Fact]
    public async Task GetPermissionsAsync_WhenProviderThrows_PropagatesException()
    {
        var provider = Substitute.For<IUserClaimsProvider>();
        provider.GetUserClaimsAsync(UserId, CompanyId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("permissions endpoint returned 503"));

        var act = async () => await CreateSut(provider).GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task GetPermissionsAsync_PassesCancellationTokenToProvider()
    {
        var provider = NewProvider();
        using var cts = new CancellationTokenSource();

        await CreateSut(provider).GetPermissionsAsync(UserId, CompanyId, cts.Token);

        await provider.Received(1).GetUserClaimsAsync(UserId, CompanyId, cts.Token);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetPermissionsAsync_WithBlankUserId_Throws(string? userId)
    {
        var provider = NewProvider();

        var act = async () => await CreateSut(provider).GetPermissionsAsync(userId!, CompanyId);

        await act.Should().ThrowAsync<ArgumentException>();
        await provider.DidNotReceive().GetUserClaimsAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetPermissionsAsync_WithBlankCompanyId_Throws(string? companyId)
    {
        var provider = NewProvider();

        var act = async () => await CreateSut(provider).GetPermissionsAsync(UserId, companyId!);

        await act.Should().ThrowAsync<ArgumentException>();
        await provider.DidNotReceive().GetUserClaimsAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AddFronteggAuth_RegistersUserPermissionsService()
    {
        await using var provider = NewHostServices().BuildServiceProvider();
        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<IUserPermissionsService>().Should().NotBeNull();
    }

    // The claims provider is a documented hook: an application registering its own after AddFronteggAuth
    // must see its own data come back through this API.
    [Fact]
    public async Task GetPermissionsAsync_UsesConsumerRegisteredClaimsProvider()
    {
        var consumerProvider = NewProvider(new Claim("permissions", "consumer.permission"));
        var services = NewHostServices();
        services.AddScoped(_ => consumerProvider);

        await using var serviceProvider = services.BuildServiceProvider();
        using var scope = serviceProvider.CreateScope();
        var result = await scope.ServiceProvider
            .GetRequiredService<IUserPermissionsService>()
            .GetPermissionsAsync(UserId, CompanyId, TestContext.Current.CancellationToken);

        result.Permissions.Should().Equal("consumer.permission");
    }

    private static UserPermissionsService CreateSut(IUserClaimsProvider provider, FronteggSettings? settings = null)
        => new(provider, Options.Create(settings ?? new FronteggSettings()));

    private static IUserClaimsProvider NewProvider(params Claim[] claims)
    {
        var provider = Substitute.For<IUserClaimsProvider>();
        provider.GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([.. claims]);

        return provider;
    }

    private static ServiceCollection NewHostServices()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{FronteggSettings.SectionName}:Authority"] = "https://auth.frontegg.test",
                [$"{FronteggSettings.SectionName}:ClientId"] = "test-client"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddFronteggAuth(configuration);

        return services;
    }
}
