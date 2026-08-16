using System.Net;
using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Frontegg;
using FronteggAuth.AspNetCore.Services;
using FronteggAuth.AspNetCore.Tests.TestSupport;
using AwesomeAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggUserClaimsProviderTests
{
    [Fact]
    public async Task GetUserClaimsAsync_EmitsRolePermissionKeyAndNumericClaims()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.ToString();
            if (url.Contains("/identity/resources/permissions/v1"))
                return TestResponses.Json("""[{"id":"p1","key":"fe.read"}]""");
            if (url.Contains("/identity/resources/roles/v1"))
                return TestResponses.Json("""[{"id":"r1","key":"admin","permissions":["p1"]}]""");
            if (url.Contains("/identity/resources/users/v3/roles"))
                return TestResponses.Json("""[{"roleIds":["r1"]}]""");
            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var provider = CreateProvider(handler);

        var claims = await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);

        claims.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == "admin");
        claims.Should().Contain(c => c.Type == "permissions" && c.Value.Contains("fe.read"));
        claims.Should().Contain(c => c.Type == "Permission" && c.Value == "123");
    }

    [Fact]
    public async Task GetUserClaimsAsync_CachesResultPerUserAndTenant()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.ToString();
            if (url.Contains("/identity/resources/permissions/v1"))
                return TestResponses.Json("[]");
            if (url.Contains("/identity/resources/roles/v1"))
                return TestResponses.Json("[]");
            return TestResponses.Json("""[{"roleIds":[]}]""");
        });

        var provider = CreateProvider(handler);

        await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);
        var countAfterFirst = handler.Requests.Count;
        await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);

        handler.Requests.Count.Should().Be(countAfterFirst);
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithSizeLimitedCache_CachesWithoutThrowing()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            var url = request.RequestUri!.ToString();
            if (url.Contains("/identity/resources/permissions/v1"))
                return TestResponses.Json("[]");
            if (url.Contains("/identity/resources/roles/v1"))
                return TestResponses.Json("[]");
            return TestResponses.Json("""[{"roleIds":[]}]""");
        });
        var provider = CreateProvider(handler, new MemoryCache(new MemoryCacheOptions { SizeLimit = 10 }));

        var act = async () => await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        var countAfterFirst = handler.Requests.Count;
        await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);
        handler.Requests.Count.Should().Be(countAfterFirst);
    }

    // Enrichment is a security boundary: a principal whose roles and permissions could not be read is not the
    // same as a principal with none, so the default has to be an exception the middleware can turn into a 401.
    [Fact]
    public async Task GetUserClaimsAsync_WhenFronteggIsUnavailable_Throws()
    {
        var handler = new TestHttpMessageHandler(_ => TestResponses.Status(HttpStatusCode.ServiceUnavailable));
        var provider = CreateProvider(handler);

        var act = async () => await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<FronteggClaimsUnavailableException>();
    }

    [Fact]
    public async Task GetUserClaimsAsync_WithFailOpenEnabled_ReturnsNoClaimsAndDoesNotCacheTheOutage()
    {
        var failing = true;
        var handler = new TestHttpMessageHandler(request =>
        {
            if (failing)
                return TestResponses.Status(HttpStatusCode.ServiceUnavailable);

            var url = request.RequestUri!.ToString();
            if (url.Contains("/identity/resources/permissions/v1"))
                return TestResponses.Json("""[{"id":"p1","key":"fe.read"}]""");
            if (url.Contains("/identity/resources/roles/v1"))
                return TestResponses.Json("""[{"id":"r1","key":"admin","permissions":["p1"]}]""");
            return TestResponses.Json("""[{"roleIds":["r1"]}]""");
        });

        var provider = CreateProvider(handler, configure: o => o.FailOpenOnClaimsUnavailable = true);

        var duringOutage = await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);
        failing = false;
        var afterRecovery = await provider.GetUserClaimsAsync("user-1", "tenant-1", TestContext.Current.CancellationToken);

        duringOutage.Should().BeEmpty();
        afterRecovery.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    private static FronteggUserClaimsProvider CreateProvider(
        TestHttpMessageHandler handler,
        IMemoryCache? cache = null,
        Action<FronteggSettings>? configure = null)
    {
        // PermissionIdMappings is id->key; DefaultPermissionIdResolver inverts it to key->id internally.
        var settings = new FronteggSettings
        {
            ApiBaseUrl = "https://api.frontegg.test",
            PermissionIdMappings = new Dictionary<int, string> { [123] = "fe.read" }
        };
        configure?.Invoke(settings);
        var options = Options.Create(settings);

        var tokenService = Substitute.For<IFronteggTokenService>();
        tokenService.GetVendorTokenAsync(Arg.Any<CancellationToken>()).Returns("vendor-token");

        return new FronteggUserClaimsProvider(
            HttpClientFactoryStub.Create(handler),
            tokenService,
            new DefaultPermissionIdResolver(options),
            cache ?? new MemoryCache(new MemoryCacheOptions()),
            options,
            NullLogger<FronteggUserClaimsProvider>.Instance);
    }
}
