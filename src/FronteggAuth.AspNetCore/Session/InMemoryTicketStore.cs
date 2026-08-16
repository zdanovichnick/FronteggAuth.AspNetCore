using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;

namespace FronteggAuth.AspNetCore.Session;

/// <summary><see cref="ITicketStore"/> backed by <see cref="IMemoryCache"/> — suitable for single-instance / development.</summary>
internal sealed class InMemoryTicketStore(IMemoryCache cache) : ITicketStore
{
    private static readonly TimeSpan DefaultExpiry = TimeSpan.FromDays(7);

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Guid.NewGuid().ToString();
        SetTicket(key, ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        SetTicket(key, ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        cache.TryGetValue(key, out AuthenticationTicket? ticket);
        return Task.FromResult(ticket);
    }

    public Task RemoveAsync(string key)
    {
        cache.Remove(key);
        return Task.CompletedTask;
    }

    private void SetTicket(string key, AuthenticationTicket ticket)
    {
        var expiry = ticket.Properties.ExpiresUtc.HasValue
            ? ticket.Properties.ExpiresUtc.Value - DateTimeOffset.UtcNow
            : DefaultExpiry;

        if (expiry <= TimeSpan.Zero)
            expiry = DefaultExpiry;

        cache.Set(key, ticket, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiry,
            Size = 1
        });
    }
}
