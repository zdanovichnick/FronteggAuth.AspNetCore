using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Middleware;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace FronteggAuth.AspNetCore.Authentication;

/// <summary>Registers and configures the Frontegg authentication schemes (smart router, cookie, JWT bearer, API-key, OIDC).</summary>
internal static class FronteggSchemeConfiguration
{
    // Per-refresh-token gates serializing concurrent cookie token refreshes; pruned after use in RefreshExpiredTokenAsync.
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> RefreshLocks = new();

    // Three-state guard bounding silent OIDC state-loss recovery within OidcRetryWindow; see RecoverOrFailAsync.
    private const string OidcRetryCookieName = ".FronteggAuth.OidcRetry";
    private static readonly TimeSpan OidcRetryWindow = TimeSpan.FromSeconds(60);

    // Number of correlation/nonce cookies tolerated before ClearStaleOidcCookies sweeps them.
    private const int StaleOidcCookieThreshold = 3;

    public static void AddFronteggSchemes(this AuthenticationBuilder builder, FronteggSettings options)
    {
        var cookieEnabled = options.EnableCookie || options.EnableOpenIdConnect;

        builder.AddPolicyScheme(FronteggAuthSchemes.Smart, "Frontegg smart scheme", policy =>
        {
            policy.ForwardDefaultSelector = context => SelectScheme(context, options);
        });

        if (cookieEnabled)
            builder.AddCookie(o => ConfigureCookie(o, options));

        if (options.EnableJwtBearer)
            builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o => ConfigureJwtBearer(o, options));

        if (options.EnableApiKey)
            builder.AddJwtBearer(FronteggAuthSchemes.ApiKey, o => ConfigureApiKey(o, options));

        if (options.EnableOpenIdConnect)
            builder.AddOpenIdConnect(FronteggAuthSchemes.OpenIdConnect, o => ConfigureOpenIdConnect(o, options));
    }

    private static string SelectScheme(HttpContext context, FronteggSettings options)
    {
        if (options.EnableApiKey && context.Request.Headers.ContainsKey(options.ApiKeyHeaderName))
            return FronteggAuthSchemes.ApiKey;

        var isBearer = context.Request.Headers.Authorization.FirstOrDefault()?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ?? false;
        if (isBearer && options.EnableJwtBearer)
            return JwtBearerDefaults.AuthenticationScheme;

        if (options.EnableCookie || options.EnableOpenIdConnect)
            return CookieAuthenticationDefaults.AuthenticationScheme;

        return options.EnableJwtBearer ? JwtBearerDefaults.AuthenticationScheme : FronteggAuthSchemes.ApiKey;
    }

    private static void ConfigureCookie(CookieAuthenticationOptions options, FronteggSettings settings)
    {
        options.SlidingExpiration = true;
        options.Cookie.Name = settings.CookieName;
        options.Cookie.SameSite = SameSiteMode.None;
        if (!string.IsNullOrEmpty(settings.CookieDomain))
            options.Cookie.Domain = settings.CookieDomain;
        options.Cookie.Path = "/";
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(settings.CookieLifetimeMinutes);

        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = context => RefreshExpiredTokenAsync(context, settings),
            OnRedirectToAccessDenied = context =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            },
            OnRedirectToLogin = context =>
            {
                if (!AuthMiddleware.AcceptsHtml(context.Request))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            }
        };
    }

    private static void ConfigureJwtBearer(JwtBearerOptions options, FronteggSettings settings)
    {
        options.Authority = settings.Authority;
        options.Audience = settings.ClientId;
        options.RequireHttpsMetadata = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = settings.ClientId,
            ValidateIssuer = true,
            ValidIssuer = settings.Authority,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = settings.ClaimTypeNames.UserId,
            RoleClaimType = settings.ClaimTypeNames.Role
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                LoggerFor(context.HttpContext, "Frontegg.JwtBearer")
                    .LogError(context.Exception, "JWT bearer authentication failed: {Error}", context.Exception.Message);
                return Task.CompletedTask;
            }
        };
    }

    private static void ConfigureApiKey(JwtBearerOptions options, FronteggSettings settings)
    {
        var apiKeyAuthority = settings.EffectiveApiTokenAuthority;
        options.Authority = apiKeyAuthority;
        options.RequireHttpsMetadata = true;

        // M2M / API-key tokens may be issued by the raw Frontegg domain while OIDC tokens use the custom domain.
        var validIssuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(apiKeyAuthority))
            validIssuers.Add(apiKeyAuthority);
        if (!string.IsNullOrEmpty(settings.Authority))
            validIssuers.Add(settings.Authority);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = validIssuers.Count > 0,
            ValidIssuers = validIssuers,
            ValidateLifetime = false,
            NameClaimType = settings.ClaimTypeNames.UserId,
            RoleClaimType = settings.ClaimTypeNames.Role
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var apiKey = context.Request.Headers[settings.ApiKeyHeaderName].FirstOrDefault();
                if (!string.IsNullOrEmpty(apiKey))
                    context.Token = apiKey;
                return Task.CompletedTask;
            },
            OnTokenValidated = context => EnrichApiKeyClaimsAsync(context, settings),
            OnAuthenticationFailed = context =>
            {
                LoggerFor(context.HttpContext, "Frontegg.ApiKey")
                    .LogError(context.Exception, "API-key authentication failed: {Error}", context.Exception.Message);
                return Task.CompletedTask;
            }
        };
    }

    private static void ConfigureOpenIdConnect(OpenIdConnectOptions options, FronteggSettings settings)
    {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.Authority = settings.Authority;
        options.ClientId = settings.ClientId;

        options.ResponseType = "code";
        options.ResponseMode = "query";
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.UsePkce = true;
        options.UseTokenLifetime = false;
        options.SignedOutRedirectUri = settings.PostLogoutRedirectUri ?? "/";

        // RemoteAuthenticationTimeout is deliberately left at the framework default (15 minutes): it becomes the
        // correlation cookie's Expires (RemoteAuthenticationOptions.CorrelationCookieBuilder.Build), and that
        // cookie is written when the challenge is issued — not when credentials are submitted. Shortening it caps
        // how long a user may sit on the Frontegg login page before the callback fails with "Correlation failed."
        // Keep the nonce on the same schedule; left at its 1-hour default, orphaned nonce cookies from abandoned
        // attempts outlive their correlation partners and accumulate in the Cookie header until it exceeds
        // Kestrel's header-size cap and every request 431s.
        options.ProtocolValidator.NonceLifetime = options.RemoteAuthenticationTimeout;

        options.CallbackPath = "/signin-oidc";
        options.SignedOutCallbackPath = "/signout-callback-oidc";

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = settings.ClientId,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = settings.ClaimTypeNames.UserId,
            RoleClaimType = settings.ClaimTypeNames.Role
        };

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("offline_access");

        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.IsEssential = true;
        options.CorrelationCookie.HttpOnly = true;

        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.IsEssential = true;
        options.NonceCookie.HttpOnly = true;

        var interactiveSignInPath = SafeLocalPath(settings.InteractiveSignInPath, "/");
        var cookieBlockedTerminus = SafeTerminus(settings.CookieBlockedRedirectUri);

        options.Events = new OpenIdConnectEvents
        {
            OnTicketReceived = context =>
            {
                // A sign-in completed: drop the recovery guard so an unrelated later state loss starts its
                // silent-recovery sequence fresh rather than being short-circuited to the failure page.
                ClearRetryCookie(context.HttpContext);
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = async context =>
            {
                LoggerFor(context.HttpContext, "Frontegg.Oidc")
                    .LogError(context.Exception, "OIDC authentication failed: {Error}", context.Exception.Message);

                await RecoverOrFailAsync(context.HttpContext, options, context.Exception, context.Properties, interactiveSignInPath, cookieBlockedTerminus);
                context.HandleResponse();
            },
            OnRemoteFailure = async context =>
            {
                LoggerFor(context.HttpContext, "Frontegg.Oidc")
                    .LogError(context.Failure, "OIDC remote failure: {Error}", context.Failure?.Message);

                await RecoverOrFailAsync(context.HttpContext, options, context.Failure, context.Properties, interactiveSignInPath, cookieBlockedTerminus);
                context.HandleResponse();
            },
            OnRedirectToIdentityProvider = context =>
            {
                // A 431 from an oversized Cookie header happens at the Kestrel layer, before this handler's normal
                // "delete correlation cookie on completion" cleanup ever runs — so abandoned attempts leave orphaned
                // correlation/nonce cookies behind. This sweep collects them; the pair for the attempt being started
                // here was already written (WriteNonceCookie/GenerateCorrelationId run before this event) but carries
                // per-attempt unique names, so it is never among the request cookies matched below.
                ClearStaleOidcCookies(context.HttpContext, options);

                var returnUrl = context.Request.Query["returnUrl"].ToString();

                if (!string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//"))
                    context.ProtocolMessage.SetParameter("returnUrl", returnUrl);

                var loginHint = context.Request.Query["loginHint"].ToString();
                if(!string.IsNullOrEmpty(loginHint))
                    context.ProtocolMessage.SetParameter("login_hint", loginHint);

                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                var redirect = settings.PostLogoutRedirectUri;
                if (!string.IsNullOrWhiteSpace(redirect))
                {
                    if (redirect.StartsWith('/'))
                        redirect = $"{context.Request.Scheme}://{context.Request.Host}{redirect}";

                    context.ProtocolMessage.PostLogoutRedirectUri = redirect;
                    context.Properties.RedirectUri = redirect;
                }

                return Task.CompletedTask;
            }
        };
    }

    private static void ClearStaleOidcCookies(HttpContext context, OpenIdConnectOptions options)
    {
        var stale = FindOidcStateCookies(context, options);

        // One in-flight attempt owns one correlation + one nonce cookie, and a user legitimately keeps a couple of
        // login tabs open. Only a genuine pileup is swept — clearing on every challenge would delete the state of
        // an attempt another tab is still completing, which surfaces as the same "Correlation failed." error.
        if (stale.Count <= StaleOidcCookieThreshold)
            return;

        DeleteOidcStateCookies(context, options, stale);
    }

    // Unconditionally purge every correlation/nonce cookie (no threshold). Used on the 431 recovery path, where the
    // pileup itself is the fault being cleared and leaving any behind risks re-tripping the upstream header limit.
    private static void ForceClearOidcCookies(HttpContext context, OpenIdConnectOptions options)
        => DeleteOidcStateCookies(context, options, FindOidcStateCookies(context, options));

    private static List<string> FindOidcStateCookies(HttpContext context, OpenIdConnectOptions options)
    {
        var correlationPrefix = options.CorrelationCookie.Name ?? ".AspNetCore.Correlation.";
        var noncePrefix = options.NonceCookie.Name ?? OpenIdConnectDefaults.CookieNoncePrefix;

        return context.Request.Cookies.Keys
            .Where(name => name.StartsWith(correlationPrefix, StringComparison.Ordinal)
                           || name.StartsWith(noncePrefix, StringComparison.Ordinal))
            .ToList();
    }

    private static void DeleteOidcStateCookies(HttpContext context, OpenIdConnectOptions options, List<string> names)
    {
        if (names.Count == 0)
            return;

        // Delete options come from the framework's own cookie builders so the path always matches what wrote the
        // cookie: correlation cookies live at the path base, nonce cookies at path base + CallbackPath. A
        // hand-rolled Path = "/" silently fails to delete the nonce cookies. Response.Cookies.Delete overrides
        // Expires itself, so the builders' future expiry is irrelevant here.
        var noncePrefix = options.NonceCookie.Name ?? OpenIdConnectDefaults.CookieNoncePrefix;
        var now = DateTimeOffset.UtcNow;
        var correlationCookieOptions = options.CorrelationCookie.Build(context, now);
        var nonceCookieOptions = options.NonceCookie.Build(context, now);

        foreach (var cookieName in names)
        {
            var isNonce = cookieName.StartsWith(noncePrefix, StringComparison.Ordinal);
            context.Response.Cookies.Delete(cookieName, isNonce ? nonceCookieOptions : correlationCookieOptions);
        }
    }

    /// <summary>
    /// Recovers a sign-in that failed on lost correlation/nonce state or an oversized-header (431) callback — an idle
    /// login page, a stale tab, an expired correlation cookie, a return from Frontegg's hosted password-reset flow, or
    /// a Cookie header bloated by orphaned OIDC cookies — without any user interaction, and without ever rendering a
    /// failure page to an interactive (HTML) request.
    ///
    /// A Frontegg-initiated callback (hosted password-reset / SSO auto-login) carries a plain-GUID <c>state</c> and no
    /// matching correlation cookie — the common recoverable case. It gets one silent re-challenge, which mints a fresh
    /// correlation+nonce pair and completes against Frontegg's still-live SSO session, so the user just lands signed
    /// in. The re-challenge lands on the caller's original same-site RedirectUri, else <paramref name="interactiveSignInPath"/>.
    ///
    /// Every other interactive failure ends without re-challenging: a callback carrying <em>our own</em> framework-issued
    /// (opaque, DataProtection-protected) <c>state</c> that still lost its correlation cookie proves the browser is not
    /// persisting the cookie, so re-launching the flow would only loop until the browser's own redirect cap. Instead the
    /// user is redirected once to <paramref name="cookieBlockedTerminus"/> — a landing that must NOT re-enter the
    /// challenge. The <c>state</c> shape is the bound, so this holds even for a browser that stores no cookies at all
    /// (where the <see cref="OidcRetryCookieName"/> guard cannot survive to count attempts). When no terminus is
    /// configured, a neutral terminal response ends the flow rather than re-challenging.
    ///
    /// A 431 additionally purges the orphaned correlation/nonce cookies that bloated the header first, so the single
    /// re-challenge starts from an empty jar; a second 431 (header still too large) falls through to the terminus.
    ///
    /// No interactive request is ever shown a failure page. Only non-interactive (non-HTML) callers — API/XHR — get a
    /// status code instead of a redirect. The retry guard is scoped to <see cref="OidcRetryWindow"/> and cleared by a
    /// completed sign-in (OnTicketReceived) or when recovery ends at the terminus.
    /// </summary>
    private static async Task RecoverOrFailAsync(
        HttpContext context, OpenIdConnectOptions options, Exception? failure,
        AuthenticationProperties? properties, string interactiveSignInPath, string? cookieBlockedTerminus)
    {
        // API / non-interactive callers get a status code — a browser HTML redirect would be meaningless to them.
        if (!AuthMiddleware.AcceptsHtml(context.Request))
        {
            await WriteAuthFailureAsync(context.Response);
            return;
        }

        var stage = context.Request.Cookies.TryGetValue(OidcRetryCookieName, out var value) ? value : null;

        if (IsHeaderTooLargeFailure(context, failure))
        {
            // The callback came back with error=431: the Cookie header was too large upstream. On the first hit, purge
            // the orphaned correlation/nonce cookies that bloated it and send the user to a clean top-level GET which
            // re-challenges from an empty jar. If it 431s again (stage set) the header is still too large even purged,
            // so stop re-challenging and end at the terminus.
            ForceClearOidcCookies(context, options);

            if (stage is null)
            {
                AppendRetryCookie(context, "1");
                LoggerFor(context, "Frontegg.Oidc")
                    .LogInformation("Cleared oversized OIDC cookie pileup after 431; redirecting to {Path}", interactiveSignInPath);
                context.Response.Redirect(interactiveSignInPath);
                return;
            }

            LoggerFor(context, "Frontegg.Oidc")
                .LogInformation("Header still too large after a 431 purge; ending recovery at terminal landing instead of re-challenging");
            await RedirectToCookieBlockedTerminusAsync(context, cookieBlockedTerminus);
            return;
        }

        var isStateLoss = failure is OpenIdConnectProtocolInvalidNonceException
                          || (failure?.Message.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase) ?? false)
                          || (failure?.Message.Contains("unable to unprotect", StringComparison.OrdinalIgnoreCase) ?? false);

        if (isStateLoss && IsFronteggInitiatedState(context) && stage is null)
        {
            // Frontegg-initiated state loss (plain-GUID state, no correlation cookie we ever wrote) — one silent
            // re-challenge. Frontegg's SSO session (still live from the reset/login that triggered this callback)
            // bounces straight back with a freshly minted correlation+nonce pair, so no page is shown. The landing
            // target is the user's original same-site RedirectUri, else the sign-in path.
            AppendRetryCookie(context, "1");
            var redirectUri = SafeLocalPath(properties?.RedirectUri, interactiveSignInPath);

            LoggerFor(context, "Frontegg.Oidc")
                .LogInformation("Restarting OIDC sign-in after Frontegg-initiated state loss; returning to {RedirectUri}", redirectUri);

            await context.ChallengeAsync(FronteggAuthSchemes.OpenIdConnect,
                new AuthenticationProperties { RedirectUri = redirectUri });
            return;
        }

        // The failing callback carries our own framework-issued state (a sign-in we launched came back with its
        // correlation cookie missing), or we have already spent the one silent re-challenge, or the failure is not a
        // recoverable state loss at all. Re-challenging would loop, so end at the terminus without re-entering the
        // challenge — no failure page for the browser. The state shape is the bound, so this stops even a browser that
        // persists no cookies (where the retry guard could never survive to count attempts).
        LoggerFor(context, "Frontegg.Oidc")
            .LogInformation("OIDC sign-in not recovered silently (stage {Stage}); ending recovery at terminal landing",
                stage ?? "none");

        await RedirectToCookieBlockedTerminusAsync(context, cookieBlockedTerminus);
    }

    // Ends recovery without re-entering the OIDC challenge: redirect once to the configured terminus (a same-site path
    // or absolute https URL that must not itself challenge), else emit a neutral terminal response. Either way the retry
    // guard is dropped so a later, unrelated sign-in attempt starts its silent recovery fresh.
    private static async Task RedirectToCookieBlockedTerminusAsync(HttpContext context, string? cookieBlockedTerminus)
    {
        ClearRetryCookie(context);

        if (cookieBlockedTerminus is not null)
        {
            context.Response.Redirect(cookieBlockedTerminus);
            return;
        }

        // No terminus configured: a neutral 200 rather than a re-challenge (which would loop) or a 500 (a failure page).
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync("Signed out. Open the app again to sign in.");
    }

    // A remote failure whose OAuth error is "431" (HTTP 431 Request Header Fields Too Large, surfaced by the IdP as an
    // authorization-error redirect): the Cookie header sent upstream was too large. Matched on the callback's error
    // query parameter (trimmed — the observed value carries a trailing space), with the framework's failure message as
    // a fallback.
    private static bool IsHeaderTooLargeFailure(HttpContext context, Exception? failure)
    {
        var error = context.Request.Query["error"].ToString().Trim();
        return string.Equals(error, "431", StringComparison.Ordinal)
               || (failure?.Message.Contains("error: '431", StringComparison.Ordinal) ?? false);
    }

    // The recovery guard: Lax (not None) because the callback from Frontegg is a top-level GET navigation, which
    // sends Lax cookies, and the marker has no reason to travel on cross-site subrequests. Path "/" so it is visible
    // to both the /signin-oidc callback and the interactive sign-in path.
    private static void AppendRetryCookie(HttpContext context, string value)
        => context.Response.Cookies.Append(OidcRetryCookieName, value, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            IsEssential = true,
            Path = "/",
            Expires = DateTimeOffset.UtcNow.Add(OidcRetryWindow)
        });

    private static void ClearRetryCookie(HttpContext context)
    {
        if (!context.Request.Cookies.ContainsKey(OidcRetryCookieName))
            return;

        // Delete options mirror AppendRetryCookie's path/attributes so the browser actually drops it.
        context.Response.Cookies.Delete(OidcRetryCookieName, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });
    }

    // Guards a redirect target: only a same-site absolute path is honoured, so neither a stored
    // AuthenticationProperties.RedirectUri nor a misconfigured setting can redirect to an attacker-supplied host.
    private static string SafeLocalPath(string? candidate, string fallback)
        => !string.IsNullOrEmpty(candidate) && candidate.StartsWith('/') && !candidate.StartsWith("//", StringComparison.Ordinal)
            ? candidate
            : fallback;

    // The recovery terminus (CookieBlockedRedirectUri) may legitimately be an absolute https URL — the SPA app root
    // typically lives on a different host than this auth API — so it is validated more permissively than SafeLocalPath:
    // a same-site absolute path, or an absolute https URL. Anything else (a relative path, http, a scheme-relative
    // "//host") is rejected to null, which drops recovery to the neutral terminal response. The value comes from trusted
    // configuration, never from the request, so an absolute host here is not an open-redirect vector.
    private static string? SafeTerminus(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
            return null;

        if (candidate.StartsWith('/') && !candidate.StartsWith("//", StringComparison.Ordinal))
            return candidate;

        return Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
            ? candidate
            : null;
    }

    // Distinguishes a Frontegg-initiated callback from a sign-in this integration launched, by the shape of the echoed
    // `state`. ASP.NET Core protects its state with DataProtection into an opaque, non-GUID token; Frontegg's hosted
    // flows (password-reset / SSO auto-login) send a plain GUID (or, defensively, no state). The check is
    // cookie-independent — Frontegg echoes `state` back on the callback URL — so it bounds recovery even when no cookie
    // survives the round trip.
    private static bool IsFronteggInitiatedState(HttpContext context)
    {
        var state = context.Request.Query["state"].ToString();
        return string.IsNullOrEmpty(state) || Guid.TryParseExact(state, "D", out _);
    }

    private static Task WriteAuthFailureAsync(HttpResponse response)
    {
        response.StatusCode = StatusCodes.Status500InternalServerError;
        response.ContentType = "text/plain";
        return response.WriteAsync("Authentication failed. Please try again.");
    }

    private static async Task RefreshExpiredTokenAsync(CookieValidatePrincipalContext context, FronteggSettings settings)
    {
        foreach (var name in settings.DeprecatedCookieNames ?? [])
        {
            if (context.Request.Cookies.ContainsKey(name))
            {
                context.Response.Cookies.Delete(name, new CookieOptions
                {
                    Domain = settings.CookieDomain,
                    Path = "/",
                    Secure = true,
                    SameSite = SameSiteMode.None
                });
            }
        }

        var expiresAt = context.Properties.GetTokenValue("expires_at");
        if (expiresAt is null || !DateTimeOffset.TryParse(expiresAt, out var expiresAtDate))
            return;

        if (expiresAtDate >= DateTimeOffset.UtcNow.AddMinutes(1))
            return;

        var refreshToken = context.Properties.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            context.RejectPrincipal();
            return;
        }

        // Serialize concurrent refreshes that share the same (rotating) refresh token: only one request performs the
        // network exchange, and siblings reuse its result from IMemoryCache. Without this, parallel requests from one
        // browser session all spend the same single-use refresh token, and every loser gets RejectPrincipal (a
        // spurious logout of a session whose sibling request just succeeded).
        var cache = context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
        var cacheKey = $"TokenRefresh:{refreshToken}";
        var gate = RefreshLocks.GetOrAdd(refreshToken, static _ => new SemaphoreSlim(1, 1));

        await gate.WaitAsync(context.HttpContext.RequestAborted);
        try
        {
            if (cache.TryGetValue(cacheKey, out List<AuthenticationToken>? cachedTokens) && cachedTokens is not null)
            {
                context.Properties.StoreTokens(cachedTokens);
                context.ShouldRenew = true;
                return;
            }

            var updatedTokens = await ExchangeRefreshTokenAsync(context, settings, refreshToken);
            if (updatedTokens is null)
            {
                context.RejectPrincipal();
                return;
            }

            cache.Set(cacheKey, updatedTokens, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30),
                Size = 1
            });
            context.Properties.StoreTokens(updatedTokens);
            context.ShouldRenew = true;
        }
        catch (Exception ex)
        {
            LoggerFor(context.HttpContext, "Frontegg.TokenRefresh")
                .LogWarning(ex, "Token refresh failed — rejecting principal");
            context.RejectPrincipal();
        }
        finally
        {
            gate.Release();
            // Best-effort prune so the lock map does not grow unbounded across rotating refresh tokens; the result
            // cache keeps correctness even if a concurrent request briefly lands on a freshly re-added semaphore.
            if (gate.CurrentCount == 1)
                RefreshLocks.TryRemove(refreshToken, out _);
        }
    }

    private static async Task<List<AuthenticationToken>?> ExchangeRefreshTokenAsync(
        CookieValidatePrincipalContext context, FronteggSettings settings, string refreshToken)
    {
        var oidcOptions = context.HttpContext.RequestServices
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(FronteggAuthSchemes.OpenIdConnect);
        var config = await oidcOptions.ConfigurationManager!
            .GetConfigurationAsync(context.HttpContext.RequestAborted);

        var client = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, config.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = settings.ClientId
            })
        };

        using var response = await client.SendAsync(request, context.HttpContext.RequestAborted);
        if (!response.IsSuccessStatusCode)
            return null;

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted));
        var root = json.RootElement;

        var updatedTokens = new List<AuthenticationToken>
        {
            new() { Name = "access_token", Value = root.GetProperty("access_token").GetString()! },
            new() { Name = "refresh_token", Value = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString()! : refreshToken },
            new()
            {
                Name = "expires_at",
                Value = DateTimeOffset.UtcNow
                    .AddSeconds(root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600)
                    .ToString("o")
            }
        };

        if (root.TryGetProperty("id_token", out var idToken))
            updatedTokens.Add(new AuthenticationToken { Name = "id_token", Value = idToken.GetString()! });

        return updatedTokens;
    }

    private static async Task EnrichApiKeyClaimsAsync(
        Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext context, FronteggSettings settings)
    {
        var claimNames = settings.ClaimTypeNames;
        var logger = LoggerFor(context.HttpContext, "Frontegg.ApiKey");

        var sub = context.Principal?.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            logger.LogWarning("API-key token missing 'sub' claim");
            context.Fail("Token missing required 'sub' claim.");
            return;
        }

        var identity = (ClaimsIdentity)context.Principal!.Identity!;

        // Always re-validate via the vendor introspection endpoint (result is cached in IAccessTokenValidationService).
        // The ApiKey scheme sets ValidateLifetime=false for long-lived keys, so revocation/expiry is enforced here —
        // not by the JWT handler. Skipping this when tenant/role claims are already present would let a revoked or
        // expired token replay indefinitely once moved into the API-key header.
        var hasTenant = identity.Claims.Any(c => c.Type.Equals(claimNames.TenantId, StringComparison.OrdinalIgnoreCase));
        var hasRoles = identity.Claims.Any(c => c.Type.Equals(claimNames.Role, StringComparison.OrdinalIgnoreCase));

        var validationService = context.HttpContext.RequestServices.GetRequiredService<IAccessTokenValidationService>();

        AccessTokenValidationResult? result;
        try
        {
            result = await validationService.ValidateAccessTokenAsync(sub, context.HttpContext.RequestAborted);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "API-key vendor-only validation failed for sub={Sub}", sub);
            context.Fail("Access token validation failed.");
            return;
        }

        if (result is null || !result.IsValid)
        {
            logger.LogWarning("API-key token failed vendor-only validation (revoked or inactive)");
            context.Fail("Access token is revoked or inactive.");
            return;
        }

        if (!hasTenant && !string.IsNullOrEmpty(result.TenantId))
            identity.AddClaim(new Claim(claimNames.TenantId, result.TenantId));

        // Resolved application user id; "externalId" is the standard fallback ClaimHelper.GetUserId checks before "sub".
        if (!string.IsNullOrEmpty(result.UserId) &&
            !identity.Claims.Any(c => c.Type.Equals("externalId", StringComparison.OrdinalIgnoreCase)))
            identity.AddClaim(new Claim("externalId", result.UserId));

        if (!string.IsNullOrEmpty(result.CreatedByUserId) &&
            !identity.Claims.Any(c => c.Type.Equals("createdByUserId", StringComparison.OrdinalIgnoreCase)))
            identity.AddClaim(new Claim("createdByUserId", result.CreatedByUserId));

        if (!hasRoles && result.Roles is { Length: > 0 })
            foreach (var role in result.Roles)
                identity.AddClaim(new Claim(claimNames.Role, role));
    }

    private static ILogger LoggerFor(HttpContext context, string category)
        => context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(category);
}
