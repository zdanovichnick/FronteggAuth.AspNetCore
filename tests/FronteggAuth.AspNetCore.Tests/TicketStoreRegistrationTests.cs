using System.Security.Claims;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.AspNetCore.Session;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using StackExchange.Redis;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

/// <summary>
/// The ticket store resolves Redis when it is first used, not while services are being registered:
/// this package's own <c>RedisConnectionString</c> connection first, then a connection the host
/// application registered, then the in-memory store.
/// </summary>
public sealed class TicketStoreRegistrationTests
{
    private const string CookieName = ".FronteggAuth";
    private const string PackageRedisConnectionString = "127.0.0.1:1";

    [Fact]
    public async Task TicketStore_WhenPackageConnectionStringConfigured_IgnoresHostConnection()
    {
        var host = NewRedis();
        var package = NewRedis();
        var services = NewServices(PackageRedisConnectionString);
        services.AddSingleton(host.Redis);
        services.AddKeyedSingleton(RedisTicketStore.ServiceKey, package.Redis);

        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<ITicketStore>().StoreAsync(NewTicket(), TestContext.Current.CancellationToken);

        package.Redis.Received().GetDatabase(Arg.Any<int>(), Arg.Any<object?>());
        host.Redis.DidNotReceive().GetDatabase(Arg.Any<int>(), Arg.Any<object?>());
    }

    // The package registers its connection under a service key, so a host application resolving
    // IConnectionMultiplexer keeps getting its own — the two point wherever each was configured to.
    [Fact]
    public async Task AddFronteggAuth_WithPackageConnectionString_LeavesHostConnectionResolvable()
    {
        var host = NewRedis();
        var package = NewRedis();
        var services = NewServices(PackageRedisConnectionString);
        services.AddSingleton(host.Redis);
        services.AddKeyedSingleton(RedisTicketStore.ServiceKey, package.Redis);

        await using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IConnectionMultiplexer>().Should().BeSameAs(host.Redis);
    }

    // The host registration lands after AddFronteggAuth has already run — the fallback only works
    // because the multiplexer is looked up when the store is resolved, not when it is registered.
    [Fact]
    public async Task TicketStore_WhenNoPackageConnectionString_FallsBackToHostConnection()
    {
        var host = NewRedis();
        var services = NewServices(redisConnectionString: null);
        services.AddSingleton(host.Redis);

        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<ITicketStore>().StoreAsync(NewTicket(), TestContext.Current.CancellationToken);

        host.Redis.Received().GetDatabase(Arg.Any<int>(), Arg.Any<object?>());
    }

    [Fact]
    public async Task TicketStore_WhenNoRedisAvailable_UsesInMemoryStore()
    {
        var services = NewServices(redisConnectionString: null);

        await using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ITicketStore>().Should().BeOfType<InMemoryTicketStore>();
    }

    // Tickets stay namespaced by cookie name because the fallback connection belongs to the host
    // application and its default database holds unrelated keys.
    [Fact]
    public async Task TicketStore_OnStore_NamespacesKeysByCookieName()
    {
        var host = NewRedis();
        var services = NewServices(redisConnectionString: null);
        services.AddSingleton(host.Redis);

        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<ITicketStore>().StoreAsync(NewTicket(), TestContext.Current.CancellationToken);

        // Matched by method name rather than a Received() overload so the assertion survives
        // StackExchange.Redis adding optional parameters to StringSetAsync.
        var key = (RedisKey)host.Database.ReceivedCalls()
            .Single(call => call.GetMethodInfo().Name == nameof(IDatabase.StringSetAsync))
            .GetArguments()[0]!;

        key.ToString().Should().StartWith($"authticket:{CookieName}:");
    }

    // A factory rather than a pre-built instance is what keeps ConnectionMultiplexer.Connect off the
    // registration path — AddFronteggAuth must not dial Redis before the host is even built.
    [Fact]
    public void AddFronteggAuth_WithPackageConnectionString_DefersConnectingUntilFirstUse()
    {
        var services = NewServices(PackageRedisConnectionString);

        var descriptor = services.Last(d =>
            d.ServiceType == typeof(IConnectionMultiplexer)
            && d.IsKeyedService
            && Equals(d.ServiceKey, RedisTicketStore.ServiceKey));

        descriptor.KeyedImplementationInstance.Should().BeNull();
        descriptor.KeyedImplementationFactory.Should().NotBeNull();
    }

    [Fact]
    public void AddFronteggAuth_WithoutPackageConnectionString_RegistersNoPackageOwnedConnection()
    {
        var services = NewServices(redisConnectionString: null);

        services.Should().NotContain(d =>
            d.ServiceType == typeof(IConnectionMultiplexer)
            && d.IsKeyedService
            && Equals(d.ServiceKey, RedisTicketStore.ServiceKey));
    }

    private static ServiceCollection NewServices(string? redisConnectionString)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{FronteggSettings.SectionName}:Authority"] = "https://auth.frontegg.test",
                [$"{FronteggSettings.SectionName}:ClientId"] = "test-client",
                [$"{FronteggSettings.SectionName}:CookieName"] = CookieName
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddFronteggAuth(configuration, o =>
        {
            o.RedisConnectionString = redisConnectionString;
        });

        return services;
    }

    private static (IConnectionMultiplexer Redis, IDatabase Database) NewRedis()
    {
        var database = Substitute.For<IDatabase>();
        var redis = Substitute.For<IConnectionMultiplexer>();
        redis.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);

        return (redis, database);
    }

    private static AuthenticationTicket NewTicket()
        => new(new ClaimsPrincipal(new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme)),
            CookieAuthenticationDefaults.AuthenticationScheme);
}
