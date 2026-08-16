using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.AspNetCore.Session;
using AwesomeAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

/// <summary>
/// A session store makes the auth cookie an opaque reference to server-side state. Attaching a per-process store
/// on a multi-instance deployment means the next request can land on an instance that cannot resolve the ticket,
/// which reads as a sign-in loop rather than an error, so the store is attached only when it is distributed.
/// </summary>
public sealed class CookieSessionStoreConfigurationTests
{
    [Fact]
    public void NoDistributedStoreConfigured_LeavesTheCookieSelfContained()
    {
        using var provider = BuildProvider();

        GetCookieOptions(provider).SessionStore.Should().BeNull();
    }

    [Fact]
    public void NoDistributedStoreConfigured_StillRegistersTheInMemoryStoreForOtherConsumers()
    {
        using var provider = BuildProvider();

        provider.GetRequiredService<ITicketStore>().Should().BeOfType<InMemoryTicketStore>();
    }

    [Fact]
    public void ConsumerRegisteredStore_IsAttachedAndKept()
    {
        var consumerStore = new FakeTicketStore();
        using var provider = BuildProvider(services => services.AddSingleton<ITicketStore>(consumerStore));

        provider.GetRequiredService<ITicketStore>().Should().BeSameAs(consumerStore);
        GetCookieOptions(provider).SessionStore.Should().BeSameAs(consumerStore);
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? configureServices = null)
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
        configureServices?.Invoke(services);
        services.AddFronteggAuth(configuration);

        return services.BuildServiceProvider();
    }

    private static CookieAuthenticationOptions GetCookieOptions(IServiceProvider provider)
        => provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

    private sealed class FakeTicketStore : ITicketStore
    {
        public Task<string> StoreAsync(AuthenticationTicket ticket) => Task.FromResult(string.Empty);

        public Task RenewAsync(string key, AuthenticationTicket ticket) => Task.CompletedTask;

        public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult<AuthenticationTicket?>(null);

        public Task RemoveAsync(string key) => Task.CompletedTask;
    }
}
