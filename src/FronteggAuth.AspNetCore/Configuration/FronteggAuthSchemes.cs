namespace FronteggAuth.AspNetCore.Configuration;

/// <summary>
/// Canonical authentication scheme names registered by the Frontegg integration.
/// The cookie and standard JWT bearer handlers use the framework default scheme names
/// (<c>Cookies</c> / <c>Bearer</c>); the names below identify the additional schemes.
/// </summary>
public static class FronteggAuthSchemes
{
    /// <summary>Policy scheme that routes each request to the cookie, JWT bearer, or API-key handler.</summary>
    public const string Smart = "Frontegg.Smart";

    /// <summary>OpenID Connect challenge scheme used for interactive login.</summary>
    public const string OpenIdConnect = "Frontegg.Oidc";

    /// <summary>JWT bearer scheme that validates Frontegg-issued API keys / machine-to-machine tokens.</summary>
    public const string ApiKey = "Frontegg.ApiKey";
}
