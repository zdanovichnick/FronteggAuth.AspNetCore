# Getting started

How to put `FronteggAuth.AspNetCore` into an ASP.NET Core application, in the order you actually need it.

- For the complete reference — every setting, every hook, the ticket store, Data Protection —
  see the [package README](../src/FronteggAuth.AspNetCore/README.md).
- For working code, see the [samples](../samples/README.md).
- For *why* the pipeline and the scheme router look the way they do, see [architecture.md](architecture.md).

## 1. What you need from Frontegg first

| Value | Where it comes from | Goes in |
|---|---|---|
| Client ID | Frontegg portal → your application | `FronteggSettings:ClientId` |
| Login domain | Frontegg portal → Authentication → Domains, e.g. `https://auth.example.com` | `FronteggSettings:Authority` |
| API base URL | Usually `https://api.frontegg.com` | `FronteggSettings:ApiBaseUrl` |
| Vendor client secret | Frontegg portal → Settings → API keys | **user-secrets / secret store**, as `FronteggSettings:ApiKey` |

If your host signs users in interactively, also register its redirect URIs in the portal:
`https://<your-host>/signin-oidc` and, for sign-out, whatever you set as `PostLogoutRedirectUri`.

`ApiKey` and `TenantSecret` are credentials. Locally:

```bash
dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
```

Anywhere else, use environment variables or a secret manager. Never a committed `appsettings.json`.

## 2. Install

```bash
dotnet add package FronteggAuth.AspNetCore
```

Targets `net8.0`, `net9.0`, `net10.0`. No cloud-provider dependency: nothing is pulled in for AWS, Azure, or
anything else unless you add it.

## 3. Configure

One section, `FronteggSettings`. Nothing is validated at startup — an omitted required value fails later, at
first use, not at `AddFronteggAuth`.

**Required** — the package cannot do anything useful without these:

| Key | Purpose |
|---|---|
| `ClientId` | OAuth client ID; also the JWT audience |
| `Authority` | Frontegg OIDC issuer (your login domain) |
| `ApiBaseUrl` | Frontegg REST API base URL |
| `ApiKey` | Vendor/M2M client secret used to obtain the vendor token for claims enrichment. Credential — keep out of source (user-secrets/env/secret store) |

**Optional** — every other key has a working default or only applies to a feature you opt into:

| Key | Default | Matters when |
|---|---|---|
| `CookieName` | `.FronteggAuth` | Always (cookie scheme) |
| `CookieDomain` | unset | Cross-subdomain SSO |
| `PostLogoutRedirectUri` | unset | OIDC sign-out |
| `InteractiveSignInPath` | `/` | Silent OIDC recovery |
| `CookieBlockedRedirectUri` | unset | Browser can't persist the correlation cookie |
| `DeprecatedCookieNames` | unset | Migrating off an old cookie name |
| `ClaimsCacheDurationSeconds` | `10` | Always (claims enrichment) |
| `FailOpenOnClaimsUnavailable` | `false` | You want role-less access during a Frontegg outage instead of a 401 |
| `AccessTokenCacheDurationSeconds` | `300` | API-key scheme |
| `CookieLifetimeMinutes` | `10080` (7 days) | Cookie scheme |
| `ApiTokenAuthority` | falls back to `Authority` | M2M/API-key tokens are issued by a different domain than interactive sign-in |
| `PermissionIdMappings` | unset | You address permissions by numeric ID as well as by key |
| `UserTokenDescription` | `frontegg-auth user token` | Cosmetic — shown in the Frontegg admin UI |
| `DataProtectionApplicationName` | `frontegg-auth` | Always — must match across every instance sharing a cookie |
| `TenantClientId` / `TenantSecret` | unset | Tenant-scoped access-token retrieval |
| `EnableCookie` / `EnableOpenIdConnect` / `EnableJwtBearer` / `EnableApiKey` | all `true` | Disable schemes you don't expose, e.g. a token-only API (see §4) |
| `ApiKeyHeaderName` | `X-API-KEY` | API-key scheme |
| `RedisConnectionString` | unset | Distributed cookie ticket store — see §7 |
| `BypassRoles` / `BypassTokenTypes` | `{ "system" }` / `{ "tenantApiToken" }` | Changing which principals skip permission checks |
| `ClaimTypeNames` | package defaults | A host renamed a claim type |

`ConfigureDataProtection` is code-only (an `Action<IDataProtectionBuilder>`), not a configuration value — set it
through the second `AddFronteggAuth` overload (§7).

```jsonc
{
  "FronteggSettings": {
    "ClientId": "your-frontegg-client-id",
    "Authority": "https://auth.example.com",
    "ApiBaseUrl": "https://api.frontegg.com",

    "CookieName": ".FronteggAuth",
    "CookieDomain": ".example.com",           // optional — cross-subdomain SSO
    "PostLogoutRedirectUri": "https://app.example.com/",

    "RedisConnectionString": "redis:6379",    // optional, but see §7

    // Only if your application also addresses permissions by number.
    "PermissionIdMappings": { "123": "fe.secure.read" }
  }
}
```

`ApiKey` and `TenantSecret` go in user-secrets or a secret store, never in this block (see §1).

Every claim-type name is configurable under `FronteggSettings:ClaimTypeNames`. You will not need that until a
value comes back empty — see the troubleshooting table.

## 4. Wire it up

Two calls, always in this shape:

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
…
app.UseRouting();
app.UseFronteggAuth();     // UseAuthentication → gating → claims enrichment → UseAuthorization
app.MapControllers();
```

`UseFronteggAuth` installs four middlewares whose order is load-bearing. It has to sit **after** `UseRouting`
(the gating middleware reads the matched endpoint) and **before** endpoints are mapped.

### The one thing to understand before anything else

The gating middleware challenges or 401s **every matched endpoint that is not explicitly anonymous**, and it
does so *before* the authorization middleware runs. Consequences:

- You do not need a fallback policy to make an app private. It already is.
- Attaching no policy does **not** make an endpoint public. Only `[AllowAnonymous]` does.
- A permission denial is decided later, by authorization, and comes back as 403 — not as a redirect to login.

### A Web API (tokens only)

```csharp
builder.Services.AddFronteggAuth(builder.Configuration, settings =>
{
    settings.EnableCookie = false;
    settings.EnableOpenIdConnect = false;
});
```

This is the switch that matters for an API. With OIDC on, an unauthenticated request whose `Accept` header
mentions `text/html` is redirected to Frontegg — so a client that sends a browser-ish `Accept` receives a login
page instead of an error. With it off, every unauthenticated request gets a flat 401. No session means no
ticket store and no Redis either.

Full host: [samples/FronteggAuth.Samples.Api](../samples/FronteggAuth.Samples.Api).

### An MVC app

Defaults are already right — cookie session, OIDC challenge, plus bearer and API-key handlers for any machine
endpoints the same host exposes:

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
builder.Services.AddControllersWithViews();
```

Full host: [samples/FronteggAuth.Samples.Mvc](../samples/FronteggAuth.Samples.Mvc).

### A Blazor Web App

Same defaults, plus the component-level authentication plumbing Blazor needs:

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
```

and `AuthorizeRouteView` in `Routes.razor` — under a plain `RouteView`, a page-level `[Authorize]` is silently
ignored.

Full host: [samples/FronteggAuth.Samples.Blazor](../samples/FronteggAuth.Samples.Blazor).

### Signing out

Two calls, both required:

```csharp
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
await HttpContext.SignOutAsync(FronteggAuthSchemes.OpenIdConnect);
```

The first clears the local session; without the second the Frontegg session survives and the next sign-in
completes silently, which is indistinguishable from sign-out being broken.

## 5. Protect something

Three surfaces, one rule. Pick by host type, not by taste:

| | Minimal API | MVC action | Blazor component |
|---|---|---|---|
| `RequireAuthorization("perm:key")` / `[Authorize(Policy = "perm:key")]` | ✅ | ✅ | ✅ |
| `[Authorize(Policy = "permid:123")]` | ✅ | ✅ | ✅ |
| `[PermissionAuthorize]`, `[PermissionIdAuthorize]`, `[RoleAuthorize]`, `[SkipAuth]` | ❌ | ✅ | ❌ |

**Default to the policy form.** Nothing registers those policies — the package's policy provider materializes
any name starting with `perm:` or `permid:` on demand, so a permission created in the Frontegg portal is usable
the moment you reference it.

```csharp
app.MapGet("/reports", …).RequireAuthorization("perm:fe.secure.read");
```

Reach for the attributes when you want something they alone offer: applying a gate to a whole controller,
stacking gates as AND, or **reverse permissions** — deny-on-presence, which has no policy equivalent.

```csharp
[PermissionAuthorize("fe.secure.read")]                                    // controller-wide
[PermissionAuthorize(ReversePermissions = new[] { "account.sandboxed" })]  // denies holders
```

The attributes are `IAuthorizationFilter`s, so outside the MVC action pipeline they are ignored — without an
error. That is the one place picking the wrong surface fails open.

All three agree on who skips checks entirely: a principal holding a role in `BypassRoles` (default `system`)
or presenting a token type in `BypassTokenTypes` (default `tenantApiToken`). Change that in one place —
`PermissionBypass` — not per call site.

## 6. Read the current user

```csharp
public sealed class MeController(IIdentityUserService identity) : ControllerBase
{
    [HttpGet("/me")]
    public async Task<ActionResult<ApplicationUser?>> Me(CancellationToken cancellationToken)
        => await identity.GetUserAsync(cancellationToken);
}
```

`User` projects only what is already on the principal. `GetUserAsync()` back-fills from the claims provider
when the enrichment middleware was skipped for this request — anonymous endpoints, unmatched routes, OIDC
callbacks. Prefer `User` on ordinary authorized endpoints; use `GetUserAsync()` when the values must be there
regardless of how the request arrived.

In an *interactive* Blazor circuit neither works: `IIdentityUserService` resolves the principal through
`IHttpContextAccessor`, and there is no HTTP context inside a circuit. Use `<AuthorizeView>` or
`AuthenticationStateProvider` there.

To look up a **different** user, inject `IUserPermissionsService` rather than reading claims yourself — claim
type names are configurable, so code that names them directly breaks when a host renames one.

## 7. Before you deploy

Two settings decide whether the app survives running on more than one instance.

**Data Protection keys must be shared.** Left unconfigured they live on the local file system, so every
instance — and every restart — has a different key ring, and cookies issued by one are unreadable by the rest.

```csharp
builder.Services.AddFronteggAuth(builder.Configuration, settings =>
{
    settings.ConfigureDataProtection = dp => dp.PersistKeysToAzureBlobStorage(blobUri, credential);
});
```

For AWS SSM Parameter Store, install `FronteggAuth.AspNetCore.DataProtection.Aws` and call
`settings.PersistDataProtectionKeysToSsm("/myapp/{environment}/dataprotection")`.

**The cookie ticket store should be distributed.** Set `FronteggSettings:RedisConnectionString` (or register an
`IConnectionMultiplexer`). Without one the package falls back to an in-memory store and deliberately leaves it
*unattached* from the cookie — a per-process ticket store behind a load balancer produces a sign-in loop rather
than an error. The cookie then stays self-contained and chunked, which works but is large; a warning is logged.

Redis is resolved the first time the store is used, not at registration, so `AddFronteggAuth` never blocks
startup on a Redis dial and does not care what order it ran in.

## 8. Make it yours

Product-specific behaviour enters through four hooks, never through a change in the package. All four defaults
are registered with `TryAdd*`, so registering your own **after** `AddFronteggAuth` wins:

| Hook | Replace it when |
|---|---|
| `IUserClaimsProvider` | Roles/permissions live somewhere other than Frontegg's API |
| `IPermissionIdResolver` | Numeric permission ids come from a database rather than `PermissionIdMappings` |
| `IAccountStatusValidator` | Access depends on account state — suspended, expired, unpaid |
| `IClaimsTransformer` | You need a role or claim derived from what the tenant does issue |

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
builder.Services.AddSingleton<IClaimsTransformer, MyClaimsTransformer>();
```

The MVC sample's [SampleClaimsTransformer](../samples/FronteggAuth.Samples.Mvc/SampleClaimsTransformer.cs)
shows the shape, including the two details worth copying: read claims under their *configured* type name, and
write roles under `identity.RoleClaimType` rather than `ClaimTypes.Role`.

The package ships no permission constants — Frontegg permission keys are tenant-defined, so any list baked into
a library would be wrong for everyone. Declare your own `static class MyPermissions`.

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Sign-in redirects forever | Ticket store is in-memory behind a load balancer, or Data Protection keys are per-instance | §7 — set `RedisConnectionString` and persist keys |
| Users signed out after every deploy | Data Protection key ring is regenerated on restart | §7 — persist the key ring |
| An HTTP client gets an HTML login page | Its `Accept` header mentions `text/html` and OIDC is enabled | Turn `EnableOpenIdConnect` off for API hosts, or send `Accept: application/json` |
| Every request 401s and you expected a login page | `EnableOpenIdConnect` is off, or the request carries an `Authorization`/API-key header | Check which of the two applies; the gating middleware only challenges header-less HTML requests |
| A `permid:` gate denies everyone | The id is not in `PermissionIdMappings`, so the numeric claim is never emitted | Add the mapping, or use the `perm:` key form |
| `[PermissionAuthorize]` seems to be ignored | It is on a minimal-API endpoint or a Blazor component | Use `perm:` policies outside MVC |
| `User.IsInRole` is false for a role you can see in the claims | Role claim type mismatch | Set `FronteggSettings:ClaimTypeNames:Role` |
| `ApplicationUser` fields are empty but the claims are present | Claim-type mapping | Compare against `ClaimTypeNames`; the API sample's `/api/diagnostics/claims` shows both sides |
| Sign-out does nothing — next login is instant | Only the cookie was cleared | Call `SignOutAsync` for `FronteggAuthSchemes.OpenIdConnect` too |
| 403 with an RFC 7807 body instead of an access-denied page | A permission filter denied an authenticated user | Expected. Handle 403 in the host (`UseStatusCodePagesWithReExecute`) if you want a page |
| HTTP 431 during sign-in | Cookie headers grew past the server limit | Use the Redis ticket store so the cookie stays small |
| 401s during a Frontegg outage | Claims enrichment fails closed by design | `FailOpenOnClaimsUnavailable = true` if a role-less principal is acceptable to you |
| A `system` user passes checks it should not | `BypassRoles` defaults to `system` | `services.PostConfigure<FronteggSettings>(s => s.BypassRoles.Clear())` — configuration alone cannot remove it, the binder only adds |

The API sample's diagnostic endpoints answer most of the above directly: `/api/diagnostics/me`,
`/api/diagnostics/claims`, and the two policy probes that report `granted: true|false` without gating on the
policy they evaluate.
