using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Authentication;

/// <summary>
/// Attaches the registered <see cref="ITicketStore"/> to the cookie authentication scheme, but only when that
/// store is reachable from every instance of the application.
///
/// A session store turns the auth cookie into an opaque reference to server-side state. With a distributed
/// store that is a win: the cookie stays small even though <c>SaveTokens</c> keeps the Frontegg tokens on the
/// ticket. With a per-process store it is a sign-in loop: whichever instance the load balancer picks next
/// cannot resolve a ticket minted by another, so the request arrives anonymous and is challenged again.
/// Leaving <see cref="CookieAuthenticationOptions.SessionStore"/> unset falls back to a self-contained
/// (chunked) cookie that any instance sharing the DataProtection key ring can validate.
/// </summary>
internal sealed class ConfigureCookieSessionStore(
    ITicketStore ticketStore,
    ILogger<ConfigureCookieSessionStore> logger,
    bool isTicketStoreDistributed) : IPostConfigureOptions<CookieAuthenticationOptions>
{
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
    {
        if (name != CookieAuthenticationDefaults.AuthenticationScheme)
            return;

        if (!isTicketStoreDistributed)
        {
            logger.LogWarning(
                "No distributed auth ticket store is configured, so the cookie scheme will use self-contained "
                + "cookies instead of {TicketStore}. Set FronteggSettings:RedisConnectionString to keep the "
                + "cookie small; note this is a different setting from ConnectionStrings:Redis.",
                ticketStore.GetType().Name);
            return;
        }

        options.SessionStore = ticketStore;
    }
}
