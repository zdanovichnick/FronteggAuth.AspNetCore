using System.Net;
using System.Text;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Frontegg;
using FronteggAuth.AspNetCore.Tests.TestSupport;
using AwesomeAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggUserTokenServiceTests
{
    [Fact]
    public async Task GetUserTokenAsync_WithValidEmail_ReturnsUserJwt()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return TestResponses.Json("""{"accessToken":"jwt-token-abc","expiresIn":3600}""");

            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var service = CreateService(handler, out _);

        var token = await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        token.Should().Be("jwt-token-abc");
        handler.Requests.Should().HaveCount(3);
    }

    [Fact]
    public async Task GetUserTokenAsync_WhenUserNotFound_ThrowsInvalidOperationException()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Status(HttpStatusCode.NotFound);

            return TestResponses.Status(HttpStatusCode.BadRequest);
        });

        var service = CreateService(handler, out _);

        var act = () => service.GetUserTokenAsync("notfound@example.com");

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Frontegg user not found*");
    }

    [Fact]
    public async Task GetUserTokenAsync_WhenPatCreationFails_ThrowsInvalidOperationException()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("Access denied", Encoding.UTF8, "application/json")
                };

            return TestResponses.Status(HttpStatusCode.BadRequest);
        });

        var service = CreateService(handler, out _);

        var act = () => service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*PAT creation failed*");
    }

    [Fact]
    public async Task GetUserTokenAsync_WhenTokenExchangeFails_ThrowsInvalidOperationException()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("Invalid credentials", Encoding.UTF8, "application/json")
                };

            return TestResponses.Status(HttpStatusCode.BadRequest);
        });

        var service = CreateService(handler, out _);

        var act = () => service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*token exchange failed*");
    }

    [Fact]
    public async Task GetUserTokenAsync_WithinExpiryBuffer_CachesTokenWithoutNewRequests()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return TestResponses.Json("""{"accessToken":"jwt-token-cached","expiresIn":3600}""");

            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var service = CreateService(handler, out var time);

        var first = await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);
        var second = await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        first.Should().Be("jwt-token-cached");
        second.Should().Be("jwt-token-cached");
        handler.Requests.Should().HaveCount(3);
    }

    [Fact]
    public async Task GetUserTokenAsync_AfterJwtExpiry_ReusesPat_NoNewPatCreation()
    {
        var requestCount = 0;
        var handler = new TestHttpMessageHandler(request =>
        {
            requestCount++;

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return TestResponses.Json("""{"accessToken":"jwt-token-refresh","expiresIn":3600}""");

            return TestResponses.Status(HttpStatusCode.BadRequest);
        });

        var service = CreateService(handler, out var time);

        await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromSeconds(3600));
        await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        // First call: user lookup + PAT creation + token exchange = 3 requests
        // Second call (after expiry): token exchange only (PAT reused) = 1 request
        // Total: 4 requests
        handler.Requests.Should().HaveCount(4);

        var patRequests = handler.Requests.Where(r => r.RequestUri?.PathAndQuery.Contains("/access-tokens/v1") == true).ToList();
        patRequests.Should().HaveCount(1, "PAT should only be created once, not again on JWT refresh");
    }

    [Fact]
    public async Task GetUserTokenAsync_DifferentEmails_MaintainsSeparateCaches()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
            {
                var email = Uri.UnescapeDataString(request.RequestUri.Query.Split("=")[1]);
                if (email.Contains("user1"))
                    return TestResponses.Json("""{"id":"user1-id","tenantId":"tenant-1"}""");
                else
                    return TestResponses.Json("""{"id":"user2-id","tenantId":"tenant-2"}""");
            }

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return TestResponses.Json("""{"accessToken":"jwt-token","expiresIn":3600}""");

            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var service = CreateService(handler, out _);

        var token1 = await service.GetUserTokenAsync("user1@example.com", TestContext.Current.CancellationToken);
        var token2 = await service.GetUserTokenAsync("user2@example.com", TestContext.Current.CancellationToken);

        token1.Should().Be("jwt-token");
        token2.Should().Be("jwt-token");
        // 3 requests per user = 6 total
        handler.Requests.Should().HaveCount(6);
    }

    [Fact]
    public async Task GetUserTokenAsync_ParsesAlternativeTokenFieldNames()
    {
        var handler = new TestHttpMessageHandler(request =>
        {
            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"id":"pat-id","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                // Response uses snake_case variants
                return TestResponses.Json("""{"access_token":"jwt-alternative","expires_in":1800}""");

            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var service = CreateService(handler, out _);

        var token = await service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken);

        token.Should().Be("jwt-alternative");
    }

    [Fact]
    public async Task GetUserTokenAsync_WithNullOrEmptyEmail_ThrowsArgumentException()
    {
        var handler = new TestHttpMessageHandler(_ => TestResponses.Status(HttpStatusCode.BadRequest));
        var service = CreateService(handler, out _);

        await service.Invoking(s => s.GetUserTokenAsync(null!))
            .Should().ThrowAsync<ArgumentException>();

        await service.Invoking(s => s.GetUserTokenAsync(""))
            .Should().ThrowAsync<ArgumentException>();

        await service.Invoking(s => s.GetUserTokenAsync("   "))
            .Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GetUserTokenAsync_ConcurrentCallsSameEmail_CreatesPatOnceAndSharesToken()
    {
        var requestCount = 0;
        var handler = new TestHttpMessageHandler(request =>
        {
            Interlocked.Increment(ref requestCount);

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/v1/email") == true)
                return TestResponses.Json("""{"id":"user-123","tenantId":"tenant-456"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/users/access-tokens/v1") == true)
                return TestResponses.Json("""{"clientId":"pat-client","secret":"pat-secret"}""");

            if (request.RequestUri?.PathAndQuery.Contains("/identity/resources/auth/v2/api-token") == true)
                return TestResponses.Json("""{"accessToken":"jwt-token-concurrent","expiresIn":3600}""");

            return TestResponses.Status(HttpStatusCode.NotFound);
        });

        var service = CreateService(handler, out _);

        // Launch 5 concurrent calls for the same email
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => service.GetUserTokenAsync("user@example.com", TestContext.Current.CancellationToken))
            .ToList();

        var tokens = await Task.WhenAll(tasks);

        // All should return the same token
        tokens.Should().AllBe("jwt-token-concurrent");

        // PAT creation should happen once: 1 user lookup + 1 PAT creation + potentially multiple token exchanges
        // Due to concurrent calls, the double-check pattern may allow multiple token exchanges if the first
        // one hasn't completed when others check the cache, but PAT creation (which is the expensive part)
        // should only happen once.
        var patRequests = handler.Requests.Where(r => r.RequestUri?.PathAndQuery.Contains("/access-tokens/v1") == true).ToList();
        patRequests.Should().HaveCount(1, "PAT should only be created once despite concurrent calls for same email");
    }

    private static FronteggUserTokenService CreateService(TestHttpMessageHandler handler, out MutableTimeProvider time)
    {
        time = new MutableTimeProvider(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var options = Options.Create(new FronteggSettings
        {
            ApiBaseUrl = "https://api.frontegg.test"
        });

        var tokenService = Substitute.For<IFronteggTokenService>();
        tokenService.GetVendorTokenAsync(Arg.Any<CancellationToken>())
            .Returns(Task.FromResult("vendor-token"));

        return new FronteggUserTokenService(
            HttpClientFactoryStub.Create(handler),
            options,
            time,
            NullLogger<FronteggUserTokenService>.Instance,
            tokenService);
    }
}
