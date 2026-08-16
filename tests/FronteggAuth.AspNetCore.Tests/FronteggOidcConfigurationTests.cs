using System.Text;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Extensions;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggOidcConfigurationTests
{
    private const string Authority = "https://auth.frontegg.test";
    private const string CorrelationPrefix = ".AspNetCore.Correlation.";
    private const string RetryCookieName = ".FronteggAuth.OidcRetry";
    private const string Terminus = "https://app.example.test/home";

    // A Frontegg-initiated callback (hosted password-reset / SSO auto-login) echoes a plain-GUID state; a sign-in this
    // integration launched echoes ASP.NET Core's opaque DataProtection-protected state. The recovery keys off that shape.
    private const string FronteggInitiatedState = "b113035b-b223-48f9-8f9e-de89f244f4d2";
    private const string FrameworkIssuedState = "CfDJ8AbcDefGhiJklMnoPqrStuVwXyZ0123456789";

    [Fact]
    public void ConfigureOpenIdConnect_CorrelationCookie_LivesForTheFrameworkRoundTripWindow()
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);
        var now = DateTimeOffset.UtcNow;

        var cookie = options.CorrelationCookie.Build(new DefaultHttpContext(), now);

        options.RemoteAuthenticationTimeout.Should().Be(TimeSpan.FromMinutes(15));
        cookie.Expires.Should().BeCloseTo(now.Add(options.RemoteAuthenticationTimeout), TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void ConfigureOpenIdConnect_NonceLifetime_MatchesCorrelationWindow()
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);

        options.ProtocolValidator.NonceLifetime.Should().Be(options.RemoteAuthenticationTimeout);
    }

    [Fact]
    public void ConfigureOpenIdConnect_NonceCookie_IsScopedToTheCallbackPath()
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);

        var cookie = options.NonceCookie.Build(new DefaultHttpContext(), DateTimeOffset.UtcNow);

        cookie.Path.Should().Be("/signin-oidc");
    }

    [Fact]
    public async Task RedirectToIdentityProvider_WithCookiePileup_DeletesEachCookieAtItsOwnPath()
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);
        var context = NewHttpContext(provider, cookieHeader: BuildCookieHeader(correlationCount: 3, nonceCount: 3));

        await InvokeRedirectToIdentityProviderAsync(options, context);

        var setCookies = context.Response.Headers.SetCookie.ToArray();
        setCookies.Where(c => c!.StartsWith(OpenIdConnectDefaults.CookieNoncePrefix, StringComparison.Ordinal))
            .Should().HaveCount(3).And.OnlyContain(c => c!.Contains("path=/signin-oidc", StringComparison.OrdinalIgnoreCase));
        setCookies.Where(c => c!.StartsWith(CorrelationPrefix, StringComparison.Ordinal))
            .Should().HaveCount(3).And.OnlyContain(c => c!.Contains("path=/", StringComparison.OrdinalIgnoreCase));
        setCookies.Should().OnlyContain(c => c!.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 1)]
    public async Task RedirectToIdentityProvider_BelowThreshold_LeavesInFlightAttemptsIntact(int correlationCount, int nonceCount)
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);
        var context = NewHttpContext(provider, cookieHeader: BuildCookieHeader(correlationCount, nonceCount));

        await InvokeRedirectToIdentityProviderAsync(options, context);

        context.Response.Headers.SetCookie.Should().BeEmpty();
    }

    [Fact]
    public async Task RemoteFailure_FronteggInitiatedStateLoss_RestartsSignInSilently()
    {
        using var provider = BuildProvider();
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, state: FronteggInitiatedState);

        await InvokeRemoteFailureAsync(options, context, new Exception("Unable to unprotect the message.State."), redirectUri: "/dashboard");

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().StartWith($"{Authority}/oauth/authorize");
        context.Response.Headers.SetCookie.Should().Contain(c => c!.StartsWith(RetryCookieName, StringComparison.Ordinal));
        (await ReadBodyAsync(context)).Should().BeEmpty();
    }

    // This is also the shape of a failed Frontegg user-impersonation login: impersonation opens the app's own Login URL
    // in a new tab, so it is an app-initiated flow carrying framework-issued (opaque) state — not a Frontegg-initiated
    // GUID-state callback. If that new tab cannot persist the correlation cookie, recovery must land on the terminus
    // without re-challenging, never silently restart against whatever SSO session is live (which could be the wrong
    // identity). Impersonation therefore never reaches the GUID-state silent-restart branch.
    [Fact]
    public async Task RemoteFailure_FrameworkIssuedStateLoss_RedirectsToTerminusWithoutReChallenge()
    {
        using var provider = BuildProvider(terminus: Terminus);
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, state: FrameworkIssuedState);

        await InvokeRemoteFailureAsync(options, context, new Exception("Correlation failed."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().Be(Terminus);
        (await ReadBodyAsync(context)).Should().BeEmpty();
    }

    [Fact]
    public async Task RemoteFailure_StateLossAfterOneSilentRestart_RedirectsToTerminusAndClearsGuard()
    {
        using var provider = BuildProvider(terminus: Terminus);
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, state: FronteggInitiatedState, cookieHeader: $"{RetryCookieName}=1");

        await InvokeRemoteFailureAsync(options, context, new Exception("Correlation failed."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().Be(Terminus);
        context.Response.Headers.SetCookie.Should().Contain(c =>
            c!.StartsWith(RetryCookieName, StringComparison.Ordinal)
            && c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RemoteFailure_NoTerminusConfigured_EndsWithNeutralResponseNotAnError()
    {
        using var provider = BuildProvider();
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, state: FrameworkIssuedState);

        await InvokeRemoteFailureAsync(options, context, new Exception("Correlation failed."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
        (await ReadBodyAsync(context)).Should().NotBeEmpty();
    }

    [Fact]
    public async Task RemoteFailure_HeaderTooLarge_PurgesOidcCookiesUnconditionallyAndRetriesFromCleanJar()
    {
        using var provider = BuildProvider();
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, cookieHeader: BuildCookieHeader(correlationCount: 2, nonceCount: 1));
        context.Request.QueryString = new QueryString("?error=431");

        await InvokeRemoteFailureAsync(options, context, new Exception("Message contains error: '431 '."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().Be("/");

        var setCookies = context.Response.Headers.SetCookie.ToArray();
        setCookies.Where(c => c!.StartsWith(CorrelationPrefix, StringComparison.Ordinal))
            .Should().HaveCount(2).And.OnlyContain(c => c!.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        setCookies.Where(c => c!.StartsWith(OpenIdConnectDefaults.CookieNoncePrefix, StringComparison.Ordinal))
            .Should().HaveCount(1).And.OnlyContain(c => c!.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        setCookies.Should().Contain(c => c!.StartsWith($"{RetryCookieName}=1", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RemoteFailure_HeaderTooLargeAfterOnePurge_PurgesAndEndsAtTerminus()
    {
        using var provider = BuildProvider(terminus: Terminus);
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(
            provider, cookieHeader: $"{RetryCookieName}=1; {CorrelationPrefix}c0=N; {OpenIdConnectDefaults.CookieNoncePrefix}n0=N");
        context.Request.QueryString = new QueryString("?error=431");

        await InvokeRemoteFailureAsync(options, context, new Exception("Message contains error: '431 '."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().Be(Terminus);

        var setCookies = context.Response.Headers.SetCookie.ToArray();
        setCookies.Should().Contain(c =>
            c!.StartsWith(CorrelationPrefix, StringComparison.Ordinal)
            && c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        setCookies.Should().Contain(c =>
            c!.StartsWith(RetryCookieName, StringComparison.Ordinal)
            && c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task TicketReceived_WithRecoveryGuard_ClearsTheGuardCookie()
    {
        using var provider = BuildProvider();
        var options = GetOidcOptions(provider);
        var context = NewHttpContext(provider, cookieHeader: $"{RetryCookieName}=1");

        await InvokeTicketReceivedAsync(options, context);

        context.Response.Headers.SetCookie.Should().Contain(c =>
            c!.StartsWith(RetryCookieName, StringComparison.Ordinal)
            && c.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task RemoteFailure_StateLossOnApiRequest_ReturnsFailureStatusNotARedirect()
    {
        using var provider = BuildProvider(terminus: Terminus);
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider, acceptsHtml: false);

        await InvokeRemoteFailureAsync(options, context, new Exception("Correlation failed."));

        context.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
        context.Response.Headers.Location.ToString().Should().BeEmpty();
        context.Response.Headers.SetCookie.Should().NotContain(c => c!.StartsWith(RetryCookieName, StringComparison.Ordinal));
    }

    [Fact]
    public async Task RemoteFailure_UnrecoverableFailureOnHtmlRequest_RedirectsToTerminus()
    {
        using var provider = BuildProvider(terminus: Terminus);
        var options = StubDiscovery(GetOidcOptions(provider));
        var context = NewHttpContext(provider);

        await InvokeRemoteFailureAsync(options, context, new Exception("access_denied"));

        context.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        context.Response.Headers.Location.ToString().Should().Be(Terminus);
        context.Response.Headers.SetCookie.Should().NotContain(c => c!.StartsWith(RetryCookieName, StringComparison.Ordinal));
    }

    private static ServiceProvider BuildProvider(string? terminus = null)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{FronteggSettings.SectionName}:Authority"] = Authority,
                [$"{FronteggSettings.SectionName}:ClientId"] = "test-client"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddFronteggAuth(configuration, o =>
        {
            o.CookieBlockedRedirectUri = terminus;
        });

        return services.BuildServiceProvider();
    }

    private static OpenIdConnectOptions GetOidcOptions(IServiceProvider provider)
        => provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(FronteggAuthSchemes.OpenIdConnect);

    /// <summary>Replaces metadata discovery with a static document so a challenge needs no network access.</summary>
    private static OpenIdConnectOptions StubDiscovery(OpenIdConnectOptions options)
    {
        options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(
            new OpenIdConnectConfiguration
            {
                Issuer = Authority,
                AuthorizationEndpoint = $"{Authority}/oauth/authorize",
                TokenEndpoint = $"{Authority}/oauth/token"
            });

        return options;
    }

    private static DefaultHttpContext NewHttpContext(
        IServiceProvider provider, bool acceptsHtml = true, string? cookieHeader = null, string? state = null)
    {
        var context = new DefaultHttpContext { RequestServices = provider.CreateScope().ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("app.example.test");
        context.Request.Path = "/signin-oidc";
        context.Response.Body = new MemoryStream();

        if (acceptsHtml)
            context.Request.Headers.Accept = "text/html,application/xhtml+xml";

        if (cookieHeader is not null)
            context.Request.Headers.Cookie = cookieHeader;

        if (state is not null)
            context.Request.QueryString = new QueryString($"?state={Uri.EscapeDataString(state)}");

        return context;
    }

    private static string BuildCookieHeader(int correlationCount, int nonceCount)
    {
        var cookies = Enumerable.Range(0, correlationCount).Select(i => $"{CorrelationPrefix}c{i}=N")
            .Concat(Enumerable.Range(0, nonceCount).Select(i => $"{OpenIdConnectDefaults.CookieNoncePrefix}n{i}=N"));

        return string.Join("; ", cookies);
    }

    private static Task InvokeRedirectToIdentityProviderAsync(OpenIdConnectOptions options, HttpContext context)
        => options.Events.OnRedirectToIdentityProvider(
            new RedirectContext(context, Scheme, options, new AuthenticationProperties())
            {
                ProtocolMessage = new OpenIdConnectMessage()
            });

    private static Task InvokeRemoteFailureAsync(
        OpenIdConnectOptions options, HttpContext context, Exception failure, string? redirectUri = null)
        => options.Events.OnRemoteFailure(
            new RemoteFailureContext(context, Scheme, options, failure)
            {
                Properties = new AuthenticationProperties { RedirectUri = redirectUri }
            });

    private static Task InvokeTicketReceivedAsync(OpenIdConnectOptions options, HttpContext context)
    {
        var ticket = new AuthenticationTicket(
            new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity()),
            FronteggAuthSchemes.OpenIdConnect);

        return options.Events.OnTicketReceived(new TicketReceivedContext(context, Scheme, options, ticket));
    }

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);

        return await reader.ReadToEndAsync();
    }

    private static AuthenticationScheme Scheme
        => new(FronteggAuthSchemes.OpenIdConnect, null, typeof(OpenIdConnectHandler));
}
