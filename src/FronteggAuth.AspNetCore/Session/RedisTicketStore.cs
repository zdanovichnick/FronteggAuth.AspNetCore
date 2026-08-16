using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using StackExchange.Redis;

namespace FronteggAuth.AspNetCore.Session;

/// <summary><see cref="ITicketStore"/> backed by Redis — suitable for multi-instance deployments.</summary>
internal sealed class RedisTicketStore(IConnectionMultiplexer redis, string keyPrefix) : ITicketStore
{
    /// <summary>DI key for the keyed <see cref="IConnectionMultiplexer"/> registration used by the ticket store.</summary>
    internal const string ServiceKey = "frontegg-auth-ticketstore";

    private static readonly TimeSpan DefaultExpiry = TimeSpan.FromDays(7);

    private IDatabase Db => redis.GetDatabase();

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Guid.NewGuid().ToString();
        await SetAsync(key, ticket);
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
        => await SetAsync(key, ticket);

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await Db.StringGetAsync(keyPrefix + key);
        return bytes.IsNull ? null : TicketSerializer.Default.Deserialize(bytes!);
    }

    public async Task RemoveAsync(string key)
        => await Db.KeyDeleteAsync(keyPrefix + key);

    private async Task SetAsync(string key, AuthenticationTicket ticket)
    {
        var bytes = TicketSerializer.Default.Serialize(ticket);

        var expiry = ticket.Properties.ExpiresUtc.HasValue
            ? ticket.Properties.ExpiresUtc.Value - DateTimeOffset.UtcNow
            : DefaultExpiry;

        if (expiry <= TimeSpan.Zero)
            expiry = DefaultExpiry;

        await Db.StringSetAsync(keyPrefix + key, bytes, expiry);
    }
}
