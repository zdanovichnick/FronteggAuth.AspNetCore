using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Frontegg;
using FronteggAuth.AspNetCore.Tests.TestSupport;
using AwesomeAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggTokenServiceTests
{
    [Fact]
    public async Task GetVendorTokenAsync_FetchesAndCachesToken()
    {
        var handler = new TestHttpMessageHandler(_ => TestResponses.Json("""{"token":"abc","expiresIn":3600}"""));
        var service = CreateService(handler, out _);

        var first = await service.GetVendorTokenAsync(TestContext.Current.CancellationToken);
        var second = await service.GetVendorTokenAsync(TestContext.Current.CancellationToken);

        first.Should().Be("abc");
        second.Should().Be("abc");
        handler.Requests.Should().HaveCount(1);
    }

    [Fact]
    public async Task GetVendorTokenAsync_RefreshesAfterExpiry()
    {
        var handler = new TestHttpMessageHandler(_ => TestResponses.Json("""{"token":"abc","expiresIn":3600}"""));
        var service = CreateService(handler, out var time);

        await service.GetVendorTokenAsync(TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromSeconds(3600));
        await service.GetVendorTokenAsync(TestContext.Current.CancellationToken);

        handler.Requests.Should().HaveCount(2);
    }

    private static FronteggTokenService CreateService(TestHttpMessageHandler handler, out MutableTimeProvider time)
    {
        time = new MutableTimeProvider(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var options = Options.Create(new FronteggSettings
        {
            ApiBaseUrl = "https://api.frontegg.test",
            ClientId = "client",
            ApiKey = "secret"
        });

        return new FronteggTokenService(
            HttpClientFactoryStub.Create(handler), options, time, NullLogger<FronteggTokenService>.Instance);
    }
}
