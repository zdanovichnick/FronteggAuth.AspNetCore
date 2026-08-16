using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Services;
using AwesomeAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public class IdentityUserServiceTests
{
    private static IdentityUserService CreateSut(params Claim[] claims)
        => CreateSut(Substitute.For<IUserClaimsProvider>(), claims);

    private static IdentityUserService CreateSut(IUserClaimsProvider claimsProvider, params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
        var accessor = new HttpContextAccessor { HttpContext = context };

        return new IdentityUserService(accessor, claimsProvider, Options.Create(new FronteggSettings()),
            NullLogger<IdentityUserService>.Instance);
    }

    [Fact]
    public void User_WhenOnlyEnrichedCompanyNameClaimPresent_UsesIt()
    {
        var sut = CreateSut(
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"),
            new Claim("companyName", "Contoso"));

        sut.User!.CompanyName.Should().Be("Contoso");
    }

    [Fact]
    public void User_WhenAccountNameMetadataPresent_PrefersItOverCompanyNameClaim()
    {
        var sut = CreateSut(
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("metadata", """{"accountName":"From Metadata"}"""),
            new Claim("companyName", "Contoso"));

        sut.User!.CompanyName.Should().Be("From Metadata");
    }

    [Theory]
    [InlineData("""{"accountName":""}""")]
    [InlineData("""{"accountName":"   "}""")]
    [InlineData("""{"accountName":null}""")]
    [InlineData("{}")]
    public void User_WhenAccountNameMetadataBlank_FallsBackToCompanyNameClaim(string metadataJson)
    {
        var sut = CreateSut(
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("metadata", metadataJson),
            new Claim("companyName", "Contoso"));

        sut.User!.CompanyName.Should().Be("Contoso");
    }

    [Fact]
    public void User_WhenCompanyNameClaimBlank_FallsBackToCustomClaims()
    {
        var sut = CreateSut(
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("companyName", "   "),
            new Claim("customClaims", """{"companyName":"Contoso"}"""));

        sut.User!.CompanyName.Should().Be("Contoso");
    }

    [Fact]
    public void User_WhenNoCompanyNameSourcePresent_IsNull()
    {
        var sut = CreateSut(
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"));

        sut.User!.CompanyName.Should().BeNull();
    }

    private static IUserClaimsProvider ProviderReturning(params Claim[] claims)
    {
        var provider = Substitute.For<IUserClaimsProvider>();
        provider.GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(claims.ToList());
        return provider;
    }

    [Fact]
    public async Task GetUserAsync_WhenPrincipalHasNoCompanyName_FetchesFromClaimsProvider()
    {
        var userId = Guid.NewGuid();
        var provider = ProviderReturning(new Claim("companyName", "Contoso"));
        var sut = CreateSut(provider,
            new Claim("sub", userId.ToString()),
            new Claim("tenantId", "4"));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.CompanyName.Should().Be("Contoso");
        await provider.Received(1).GetUserClaimsAsync(userId.ToString(), "4", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_MergesEveryFetchedClaim_NotOnlyCompanyName()
    {
        var provider = ProviderReturning(
            new Claim("companyName", "Contoso"),
            new Claim("Permission", "4,3550,22928"),
            new Claim(ClaimTypes.Role, "report-viewer"));
        var sut = CreateSut(provider,
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.PermissionIds.Should().Equal(4, 3550, 22928);
        user.Roles.Should().Contain("report-viewer");
    }

    [Fact]
    public async Task GetUserAsync_WhenPrincipalHasCompanyNameButNoPermissions_StillFetchesFromClaimsProvider()
    {
        var userId = Guid.NewGuid();
        var provider = ProviderReturning(new Claim("Permission", "4"));
        var sut = CreateSut(provider,
            new Claim("sub", userId.ToString()),
            new Claim("tenantId", "4"),
            new Claim("companyName", "From Principal"));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.CompanyName.Should().Be("From Principal");
        user.PermissionIds.Should().Equal(4);
        await provider.Received(1).GetUserClaimsAsync(userId.ToString(), "4", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_WhenPrincipalAlreadyFullyEnriched_DoesNotCallClaimsProvider()
    {
        var provider = ProviderReturning(new Claim("companyName", "From Provider"));
        var sut = CreateSut(provider,
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"),
            new Claim("companyName", "From Principal"),
            new Claim("permissions", "fe.secure.read"),
            new Claim("Permission", "4"));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.CompanyName.Should().Be("From Principal");
        await provider.DidNotReceive().GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_WhenCompanyNameStillUnresolved_FetchesOnlyOncePerRequest()
    {
        var provider = ProviderReturning(new Claim("Permission", "4"));
        var sut = CreateSut(provider,
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"));

        await sut.GetUserAsync(TestContext.Current.CancellationToken);
        await sut.GetUserAsync(TestContext.Current.CancellationToken);

        await provider.Received(1).GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_WhenClaimsProviderThrows_ReturnsUnenrichedUser()
    {
        var provider = Substitute.For<IUserClaimsProvider>();
        provider.GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<List<Claim>>>(_ => throw new HttpRequestException("permissions endpoint down"));
        var sut = CreateSut(provider,
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"),
            new Claim("name", "Jamie Rivera"));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.CompanyName.Should().BeNull();
        user.Name.Should().Be("Jamie Rivera");
    }

    [Fact]
    public async Task GetUserAsync_WhenTenantIdMissing_DoesNotCallClaimsProvider()
    {
        var provider = ProviderReturning(new Claim("companyName", "Contoso"));
        var sut = CreateSut(provider, new Claim("sub", Guid.NewGuid().ToString()));

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user!.CompanyName.Should().BeNull();
        await provider.DidNotReceive().GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_WhenUnauthenticated_ReturnsNull()
    {
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity()) };
        var provider = ProviderReturning(new Claim("companyName", "Contoso"));
        var sut = new IdentityUserService(new HttpContextAccessor { HttpContext = context }, provider,
            Options.Create(new FronteggSettings()), NullLogger<IdentityUserService>.Instance);

        var user = await sut.GetUserAsync(TestContext.Current.CancellationToken);

        user.Should().BeNull();
        await provider.DidNotReceive().GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetUserAsync_WhenCancelled_PropagatesCancellation()
    {
        var provider = Substitute.For<IUserClaimsProvider>();
        provider.GetUserClaimsAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns<Task<List<Claim>>>(_ => throw new OperationCanceledException());
        var sut = CreateSut(provider,
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("tenantId", "4"));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await sut.Invoking(s => s.GetUserAsync(cts.Token)).Should().ThrowAsync<OperationCanceledException>();
    }
}
