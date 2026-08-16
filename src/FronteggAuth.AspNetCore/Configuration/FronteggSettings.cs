using Microsoft.AspNetCore.DataProtection;

namespace FronteggAuth.AspNetCore.Configuration;

/// <summary>
/// Root configuration for the Frontegg authentication and authorization integration.
/// Bind from the <c>FronteggSettings</c> configuration section.
/// </summary>
public sealed class FronteggSettings
{
    /// <summary>Configuration section this binds to.</summary>
    public const string SectionName = "FronteggSettings";

    /// <summary>Frontegg OAuth client ID (also used as the JWT audience).</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Frontegg OIDC authority (your Frontegg login domain), e.g. <c>https://auth.example.com</c>.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Frontegg REST API base URL.</summary>
    public string ApiBaseUrl { get; set; } = string.Empty;

    /// <summary>Frontegg vendor/M2M client secret (API key) used to obtain a vendor token.</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Session cookie name.</summary>
    public string CookieName { get; set; } = ".FronteggAuth";

    /// <summary>Optional cookie domain for cross-subdomain sharing.</summary>
    public string? CookieDomain { get; set; }

    /// <summary>Post-logout redirect URI for OIDC sign-out.</summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// App-local path the interactive OIDC flow returns to when a lost-correlation/nonce callback is recovered
    /// without user interaction (see the silent recovery in the OIDC failure handlers). Must start with a single
    /// '/'; a non-local value is ignored in favour of the site root. Defaults to the site root.
    /// </summary>
    public string InteractiveSignInPath { get; set; } = "/";

    /// <summary>
    /// Terminal landing the silent OIDC recovery redirects to exactly once when a browser proves it cannot persist
    /// the correlation cookie — a sign-in this integration itself launched came back with its state lost, so a
    /// re-challenge would only loop until the browser's own redirect cap. Unlike <see cref="InteractiveSignInPath"/>,
    /// this target MUST NOT re-enter the OIDC challenge (point it at an app page that renders for anonymous users,
    /// not at a path that immediately challenges). Accepts a same-site absolute path (single leading '/') or an
    /// absolute <c>https</c> URL; any other value is ignored. When unset, recovery ends with a neutral terminal
    /// response rather than re-challenging.
    /// </summary>
    public string? CookieBlockedRedirectUri { get; set; }

    /// <summary>Legacy cookie names to delete on principal validation.</summary>
    public string[]? DeprecatedCookieNames { get; set; }

    /// <summary>How long enriched user claims are cached, in seconds. Failed lookups are never cached.</summary>
    public int ClaimsCacheDurationSeconds { get; set; } = 10;

    /// <summary>
    /// Whether an unreachable claims authority downgrades the request instead of rejecting it. Defaults to
    /// <see langword="false"/>: a failure surfaces as
    /// <see cref="FronteggAuth.AspNetCore.Abstractions.FronteggClaimsUnavailableException"/> and the
    /// claims-enrichment middleware returns 401. Setting it to <see langword="true"/> lets the request continue
    /// with an authenticated but role- and permission-less principal — permission-gated endpoints then return
    /// 403, but an endpoint carrying only <c>[Authorize]</c> succeeds. Only enable it if that is genuinely the
    /// behaviour you want during an outage.
    /// </summary>
    public bool FailOpenOnClaimsUnavailable { get; set; }

    /// <summary>How long API-key validation results are cached, in seconds.</summary>
    public int AccessTokenCacheDurationSeconds { get; set; } = 300;

    /// <summary>Cookie sliding-expiration window, in minutes.</summary>
    public int CookieLifetimeMinutes { get; set; } = 7 * 24 * 60;

    /// <summary>
    /// Optional issuer/authority override for machine-to-machine and API-key tokens, when those
    /// are issued by the raw Frontegg domain rather than your custom OIDC domain. Read through
    /// <see cref="EffectiveApiTokenAuthority"/>, which falls back to <see cref="Authority"/>.
    /// </summary>
    public string? ApiTokenAuthority { get; set; }

    /// <summary>
    /// The authority machine-to-machine and API-key tokens are validated against:
    /// <see cref="ApiTokenAuthority"/> when set, otherwise <see cref="Authority"/>. Always read this rather
    /// than <see cref="ApiTokenAuthority"/> directly — an unset override must fall back, not validate against
    /// an empty issuer.
    /// </summary>
    public string EffectiveApiTokenAuthority =>
        string.IsNullOrWhiteSpace(ApiTokenAuthority) ? Authority : ApiTokenAuthority;

    /// <summary>
    /// Optional map from numeric permission ID to Frontegg permission key. When supplied, the default claims
    /// provider also emits numeric permission claims for
    /// <see cref="FronteggAuth.AspNetCore.Authorization.PermissionIdAuthorizeAttribute"/>. Leave it unset if
    /// your application addresses permissions only by their Frontegg keys.
    /// </summary>
    public Dictionary<int, string>? PermissionIdMappings { get; set; }

    /// <summary>
    /// Description attached to the personal access tokens this package creates on a user's behalf. It is sent
    /// to Frontegg and shown in their admin UI, so name it after the calling application.
    /// </summary>
    public string UserTokenDescription { get; set; } = "frontegg-auth user token";

    /// <summary>
    /// Optional hook for configuring Data Protection key persistence. The package always calls
    /// <c>AddDataProtection().SetApplicationName(<see cref="DataProtectionApplicationName"/>)</c>; this callback
    /// then chooses where the key ring lives. Left <see langword="null"/>, keys stay at the ASP.NET Core default
    /// (the local file system), which does not survive across instances — configure a shared store before running
    /// behind more than one process, e.g. via the <c>FronteggAuth.AspNetCore.DataProtection.Aws</c> companion
    /// package or any other <see cref="IDataProtectionBuilder"/> persistence provider.
    /// </summary>
    public Action<IDataProtectionBuilder>? ConfigureDataProtection { get; set; }

    /// <summary>Data Protection application name (shared key-ring discriminator).</summary>
    public string DataProtectionApplicationName { get; set; } = "frontegg-auth";

    /// <summary>Tenant-scoped OAuth client ID (for tenant access-token retrieval).</summary>
    public string? TenantClientId { get; set; }

    /// <summary>Tenant-scoped OAuth client secret (for tenant access-token retrieval).</summary>
    public string? TenantSecret { get; set; }

    // Operational settings (no legacy Parameter Store equivalent)

    /// <summary>Register the cookie + OpenID Connect interactive login schemes.</summary>
    public bool EnableCookie { get; set; } = true;

    /// <summary>Register the OpenID Connect challenge scheme. Requires <see cref="EnableCookie"/>.</summary>
    public bool EnableOpenIdConnect { get; set; } = true;

    /// <summary>Register the standard JWT bearer scheme for API access tokens.</summary>
    public bool EnableJwtBearer { get; set; } = true;

    /// <summary>Register the Frontegg API-key bearer scheme.</summary>
    public bool EnableApiKey { get; set; } = true;

    /// <summary>Header that carries the Frontegg API key.</summary>
    public string ApiKeyHeaderName { get; set; } = "X-API-KEY";

    /// <summary>
    /// Optional Redis connection string for the cookie session ticket store. This is the package's own
    /// connection, opened independently of the host application's Redis even when both point at the same
    /// server, and it takes precedence over any <c>IConnectionMultiplexer</c> the host has registered.
    /// With neither available the in-memory ticket store is used and left unattached from the cookie.
    /// </summary>
    public string? RedisConnectionString { get; set; }

    /// <summary>
    /// Roles that bypass every permission check, matched case-insensitively against the
    /// <see cref="FronteggClaimTypeOptions.Role"/> claim. Defaults to
    /// <see cref="FronteggAuth.AspNetCore.Models.FronteggRoles.System"/>. Clearing the set makes every principal
    /// prove an explicit permission claim, but it has to be done in code — the configuration binder adds to the
    /// existing collection rather than replacing it, so no configuration value can remove the default:
    /// <c>services.PostConfigure&lt;FronteggSettings&gt;(s =&gt; s.BypassRoles.Clear())</c>.
    /// </summary>
    public ISet<string> BypassRoles { get; set; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Models.FronteggRoles.System };

    /// <summary>
    /// Token types that bypass permission checks the same way <see cref="BypassRoles"/> does, matched
    /// case-insensitively against the <see cref="FronteggClaimTypeOptions.TokenType"/> claim. Defaults to
    /// <see cref="FronteggAuth.AspNetCore.Models.FronteggTokenTypes.TenantApiToken"/>. Clearing the set
    /// makes every credential prove an explicit permission claim, but it has to be done in code — the
    /// configuration binder adds to the existing collection rather than replacing it, so no configuration value
    /// can remove the default:
    /// <c>services.PostConfigure&lt;FronteggSettings&gt;(s =&gt; s.BypassTokenTypes.Clear())</c>.
    /// </summary>
    public ISet<string> BypassTokenTypes { get; set; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Models.FronteggTokenTypes.TenantApiToken };

    /// <summary>Configurable claim-type names.</summary>
    public FronteggClaimTypeOptions ClaimTypeNames { get; set; } = new();
}
