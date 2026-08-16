using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Authentication;
using FronteggAuth.AspNetCore.Authorization;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Frontegg;
using FronteggAuth.AspNetCore.Middleware;
using FronteggAuth.AspNetCore.Services;
using FronteggAuth.AspNetCore.Session;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace FronteggAuth.AspNetCore.Extensions;

/// <summary>Public entry points that register and activate the Frontegg authentication/authorization integration.</summary>
public static class FronteggAuthExtensions
{
    /// <summary>
    /// Registers Frontegg authentication (smart scheme router over cookie/OIDC, JWT bearer, and API-key schemes),
    /// authorization (default policy, permission handlers, dynamic policy provider), the Frontegg API clients,
    /// and the pluggable hook defaults. Bind configuration from the <c>FronteggSettings</c> section and optionally
    /// adjust in code via <paramref name="configure"/>.
    /// </summary>
    public static IServiceCollection AddFronteggAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<FronteggSettings>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new FronteggSettings();
        configuration.GetSection(FronteggSettings.SectionName).Bind(options);
        configure?.Invoke(options);

        services.AddOptions<FronteggSettings>()
            .Bind(configuration.GetSection(FronteggSettings.SectionName))
            .Configure(o => configure?.Invoke(o));

        RegisterCoreServices(services);
        ApplyDataProtection(services, options);
        ConfigureTicketStore(services, options);

        if (options.EnableCookie || options.EnableOpenIdConnect)
        {
            services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>>(sp =>
            {
                var ticketStore = sp.GetRequiredService<ITicketStore>();

                return new ConfigureCookieSessionStore(
                    ticketStore,
                    sp.GetRequiredService<ILogger<ConfigureCookieSessionStore>>(),
                    ticketStore is not InMemoryTicketStore);
            });
        }

        var defaultChallenge = options.EnableOpenIdConnect
            ? FronteggAuthSchemes.OpenIdConnect
            : options.EnableJwtBearer ? JwtBearerDefaults.AuthenticationScheme : FronteggAuthSchemes.ApiKey;

        services
            .AddAuthentication(o =>
            {
                o.DefaultScheme = FronteggAuthSchemes.Smart;
                o.DefaultChallengeScheme = defaultChallenge;
            })
            .AddFronteggSchemes(options);

        RegisterAuthorization(services, options);

        return services;
    }

    /// <summary>
    /// Adds the Frontegg request pipeline: <c>UseAuthentication</c> → gating middleware → claims-enrichment
    /// middleware → <c>UseAuthorization</c>. Call after routing and before endpoint mapping.
    /// </summary>
    public static IApplicationBuilder UseFronteggAuth(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseAuthentication();
        app.UseMiddleware<AuthMiddleware>();
        app.UseMiddleware<UpdateClaimsMiddleware>();
        app.UseAuthorization();

        return app;
    }

    private static void RegisterCoreServices(IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddHttpContextAccessor();
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpClient(FronteggHttpClients.Api);

        services.TryAddSingleton<IFronteggTokenService, FronteggTokenService>();
        services.TryAddSingleton<IFronteggAccountTokenService, FronteggAccountTokenService>();
        // Singleton because it caches personal access tokens per email in its own fields and re-exchanges
        // them on expiry — a scoped instance would mint a new PAT on every request.
        services.TryAddSingleton<IFronteggUserTokenService, FronteggUserTokenService>();
        services.TryAddSingleton<IPermissionIdResolver, DefaultPermissionIdResolver>();
        services.TryAddScoped<IAccessTokenValidationService, AccessTokenValidationService>();
        services.TryAddScoped<IUserClaimsProvider, FronteggUserClaimsProvider>();
        services.TryAddScoped<IUserPermissionsService, UserPermissionsService>();
        services.TryAddScoped<IIdentityUserService, IdentityUserService>();
        services.TryAddSingleton<IAccountStatusValidator, NullAccountStatusValidator>();
        services.TryAddSingleton<IClaimsTransformer, NullClaimsTransformer>();
    }

    private static void RegisterAuthorization(IServiceCollection services, FronteggSettings options)
    {
        var schemes = new List<string>();
        if (options.EnableCookie || options.EnableOpenIdConnect)
            schemes.Add(CookieAuthenticationDefaults.AuthenticationScheme);
        if (options.EnableJwtBearer)
            schemes.Add(JwtBearerDefaults.AuthenticationScheme);
        if (options.EnableApiKey)
            schemes.Add(FronteggAuthSchemes.ApiKey);

        services.AddAuthorization(o =>
        {
            var builder = schemes.Count > 0
                ? new AuthorizationPolicyBuilder([.. schemes])
                : new AuthorizationPolicyBuilder();
            o.DefaultPolicy = builder.RequireAuthenticatedUser().Build();
        });

        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, PermissionIdAuthorizationHandler>();
        services.TryAddSingleton<IAuthorizationPolicyProvider, FronteggPolicyProvider>();
    }

    /// <summary>
    /// Sets up Data Protection with a stable application name — the key ring's discriminator, which must match
    /// across every instance sharing a cookie — and hands the builder to
    /// <see cref="FronteggSettings.ConfigureDataProtection"/> to choose where keys are persisted. The package
    /// itself takes no dependency on any persistence provider; without a callback the ASP.NET Core default
    /// (local file system) applies, which is per-instance and therefore only viable single-process.
    /// </summary>
    private static void ApplyDataProtection(IServiceCollection services, FronteggSettings options)
    {
        var builder = services.AddDataProtection();

        if (!string.IsNullOrWhiteSpace(options.DataProtectionApplicationName))
            builder.SetApplicationName(options.DataProtectionApplicationName);

        options.ConfigureDataProtection?.Invoke(builder);
    }

    /// <summary>
    /// Registers the cookie ticket store. Redis is resolved when the store is first used — not here —
    /// so the host application's own registrations are visible and startup never blocks on a Redis dial.
    /// Order: this package's own <see cref="FronteggSettings.RedisConnectionString"/> connection, then
    /// a host-registered <see cref="IConnectionMultiplexer"/>, then the in-memory store.
    /// </summary>
    private static void ConfigureTicketStore(IServiceCollection services, FronteggSettings options)
    {
        var keyPrefix = $"authticket:{options.CookieName}:";

        // This package's own connection, kept separate from whatever Redis the host application uses
        // even when both point at the same server. A factory (rather than a pre-built instance) means
        // the container both creates it lazily and disposes it on shutdown; the keyed registration
        // keeps it from colliding with — or being mistaken for — the host's own IConnectionMultiplexer.
        if (!string.IsNullOrWhiteSpace(options.RedisConnectionString))
        {
            services.AddKeyedSingleton<IConnectionMultiplexer>(
                RedisTicketStore.ServiceKey,
                (_, _) => ConnectionMultiplexer.Connect(BuildRedisOptions(options)));
        }

        services.TryAddSingleton<ITicketStore>(sp =>
        {
            var redis = sp.GetKeyedService<IConnectionMultiplexer>(RedisTicketStore.ServiceKey) ?? sp.GetService<IConnectionMultiplexer>();

            return redis is null
                ? new InMemoryTicketStore(sp.GetRequiredService<IMemoryCache>())
                : new RedisTicketStore(redis, keyPrefix);
        });
    }

    /// <summary>Connection tuning for the package-owned multiplexer. Never applied to a host-supplied one.</summary>
    private static ConfigurationOptions BuildRedisOptions(FronteggSettings options)
    {
        var redisOptions = ConfigurationOptions.Parse(options.RedisConnectionString!);
        redisOptions.AbortOnConnectFail = false;
        redisOptions.ConnectRetry = 3;
        redisOptions.ConnectTimeout = 5000;
        redisOptions.SyncTimeout = 5000;
        redisOptions.AsyncTimeout = 5000;
        redisOptions.KeepAlive = 60;
        redisOptions.ClientName = $"Frontegg:{options.CookieName}";

        return redisOptions;
    }
}
