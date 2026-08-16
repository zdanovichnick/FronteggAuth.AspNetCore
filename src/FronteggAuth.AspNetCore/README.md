# FronteggAuth.AspNetCore

[Frontegg CIAM](https://developers.frontegg.com/ciam/api/overview) authentication and authorization for
ASP.NET Core, in one `AddFronteggAuth` call.

Targets `net8.0`, `net9.0`, and `net10.0`.

## What it does

`AddFronteggAuth` registers a **smart scheme router** over three credential types, and routes each request to
the right one automatically:

| Credential on the request | Scheme used |
|---|---|
| API-key header (default `X-API-KEY`) | `Frontegg.ApiKey` — Frontegg API keys / M2M tokens, validated against Frontegg's vendor introspection endpoint |
| `Authorization: Bearer …` | `Bearer` — standard JWT bearer validation |
| Neither | `Cookies` — the interactive session, challenged over OpenID Connect |

On top of that it gives you automatic refresh-token renewal, recovery from the OIDC failure modes that
otherwise surface to a user as a blank error page, an optional Redis-backed cookie session store, and three
interchangeable ways to express a permission gate.

The package carries **no business rules**. Every claim-type name is configurable and every product-specific
decision enters through an injectable hook, so nothing in it assumes a particular tenant's role or permission
vocabulary.

## Install

```bash
dotnet add package FronteggAuth.AspNetCore
```

## Configure

Bind from the `FronteggSettings` section:

```jsonc
{
  "FronteggSettings": {
    "ClientId": "your-frontegg-client-id",
    "Authority": "https://auth.example.com",   // your Frontegg login domain (the OIDC issuer)
    "ApiBaseUrl": "https://api.frontegg.com",  // Frontegg REST API

    "ApiKey": "your-vendor-m2m-secret",        // vendor secret for the management API — keep it out of source
    "CookieName": ".FronteggAuth",
    "CookieDomain": ".example.com",            // optional, for cross-subdomain SSO
    "RedisConnectionString": "redis:6379",     // optional; this package's own Redis connection

    // Optional: numeric permission ID → Frontegg permission key. Supply it only if your application
    // addresses permissions by number as well as by key.
    "PermissionIdMappings": { "123": "fe.secure.read", "124": "fe.secure.write" },

    // Optional: tenant client credentials, for tenant-scoped tokens
    "TenantClientId": "…",
    "TenantSecret": "…"
  }
}
```

`ApiKey` and `TenantSecret` are credentials. Put them in user-secrets, environment variables, or your secret
store — not in a committed `appsettings.json`.

## Register & activate

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddFronteggAuth(builder.Configuration);

var app = builder.Build();

app.UseRouting();
app.UseFronteggAuth();   // UseAuthentication → gating → claims enrichment → UseAuthorization
app.MapControllers();

app.Run();
```

`UseFronteggAuth` installs four pieces of middleware in an order that matters; call it after `UseRouting` and
before you map endpoints.

A second overload adjusts settings in code, which is how you reach the options that are delegates rather than
values:

```csharp
builder.Services.AddFronteggAuth(builder.Configuration, options =>
{
    options.ConfigureDataProtection = dp => dp.PersistKeysToAzureBlobStorage(blobUri, credential);
});
```

## Authorize

Three surfaces, one rule. They agree because they share a single definition of unconditional access: a
principal holding a role in `BypassRoles` (default `system`) or presenting a token type in `BypassTokenTypes`
(default `tenantApiToken`) passes every permission check.

### Attributes

These are `IAuthorizationFilter`s, so they run in the **MVC pipeline only** — a minimal-API delegate or a
Razor Component never invokes them. Use policies there instead.

```csharp
// Native Frontegg permission keys (any-of); denied outright if the user holds a ReversePermission.
[PermissionAuthorize("fe.secure.read")]
public IActionResult Read() => Ok();

// Numeric permission IDs (any-of). Requires PermissionIdMappings or a custom IPermissionIdResolver;
// without one, no numeric claim is ever emitted and this denies everyone.
[PermissionIdAuthorize(123)]
public IActionResult ReadById() => Ok();

// Roles (any-of).
[RoleAuthorize("admin", "editor")]
public IActionResult Manage() => Ok();

// Opt an endpoint out of the package's filters entirely.
[SkipAuth]
public IActionResult Public() => Ok();
```

### Global filter (every controller)

```csharp
builder.Services.AddControllers(options =>
{
    options.Filters.Add(new PermissionAuthorizeAttribute("fe.secure.read"));

    // A reverse permission hard-denies its holders even when the forward check would pass:
    // options.Filters.Add(new PermissionIdAuthorizeAttribute(123) { ReversePermissions = [456] });
});
```

Mark the actions that must stay public — sign-in, health checks — with `[SkipAuth]` or `[AllowAnonymous]`.

### Policies (controllers *or* minimal APIs)

The dynamic policy provider materializes permission policies on demand, so there is nothing to register per
permission:

```csharp
app.MapGet("/secure", () => "ok").RequireAuthorization("perm:fe.secure.read");
app.MapGet("/by-id",  () => "ok").RequireAuthorization("permid:123");

[Authorize(Policy = "perm:fe.secure.read")]
public IActionResult Read() => Ok();
```

Policies have no reverse-permission concept — that exists only on the attributes.

## The current user

Inject `IIdentityUserService` for a strongly-typed view of the principal:

```csharp
public sealed class MeController(IIdentityUserService identity) : ControllerBase
{
    [HttpGet("/me")]
    public ActionResult<ApplicationUser?> Me() => identity.User;
}
```

`ApplicationUser` exposes permissions in both representations: `Permissions` (native Frontegg keys such as
`fe.secure.read`) and `PermissionIds` (numeric, populated only for keys that `IPermissionIdResolver` maps).

### `User` vs `GetUserAsync()`

`User` projects whatever claims are already on the principal. The claims-enrichment middleware normally puts
the enriched ones there first — but it is skipped for `[AllowAnonymous]` endpoints, unmatched routes, and the
OIDC callbacks, and it does nothing when the credential carries no user/tenant id. On those paths
`CompanyName`, `PermissionIds`, and `Roles` come back empty.

`GetUserAsync()` closes that gap: when the principal yields no company name it fetches claims from
`IUserClaimsProvider`, merges them into the principal, and re-projects. The fetch happens at most once per
request, is skipped when a company name is already present, and **fails open** — a provider outage logs a
warning and returns the unenriched user rather than throwing. That is safe here specifically because
authorization has already been decided by the time it runs, so an unenriched projection cannot widen access.

```csharp
[HttpGet("/me")]
public async Task<ActionResult<ApplicationUser?>> Me(CancellationToken cancellationToken)
    => await identity.GetUserAsync(cancellationToken);
```

Prefer `User` on ordinary authorized endpoints; reach for `GetUserAsync()` when the values must be present
regardless of the path.

## Another user's permissions

`IIdentityUserService` only ever describes the current request. To look up a **different** user — an admin
screen, a background job, an impersonation check — inject `IUserPermissionsService`:

```csharp
public sealed class AdminService(IUserPermissionsService permissions)
{
    public async Task<bool> CanEditAsync(string userId, string tenantId, CancellationToken cancellationToken)
    {
        var result = await permissions.GetPermissionsAsync(userId, tenantId, cancellationToken);

        return result.Permissions.Contains("fe.secure.write");
    }
}

public sealed record UserPermissions(
    string[] Permissions,     // native Frontegg keys
    int[]    PermissionIds,   // numeric IDs, for the keys IPermissionIdResolver maps
    string[] Roles);          // role keys held within the tenant
```

This is a projection over `IUserClaimsProvider`; it adds no data path of its own. It exists so callers never
name the claim types themselves — those names are configurable, so an application that reads claims directly
breaks silently the moment a host renames one.

Two behaviours worth knowing:

- **Failures propagate.** A provider outage throws rather than returning an empty set, because "no
  permissions" and "could not read permissions" are indistinguishable to a caller and the difference can widen
  access for an inverted check. Handle the exception; do not treat it as an empty set. (This is the opposite of
  `GetUserAsync()`, and deliberately so — see above.)
- **Results are cached** per user+tenant for `ClaimsCacheDurationSeconds` (default 10). Repeat calls are cheap
  but may lag a permission change by that window. There is no invalidation hook.

## Fail-closed claims enrichment

If the claims authority is unreachable, the default is to **reject the request**: the provider throws
`FronteggClaimsUnavailableException` and the enrichment middleware returns 401. A principal whose roles could
not be read is not the same as a principal with no roles.

Setting `FailOpenOnClaimsUnavailable = true` lets the request continue with an authenticated but role- and
permission-less principal — permission-gated endpoints then return 403 while a bare `[Authorize]` endpoint
succeeds. Enable it only if that is genuinely what you want during an outage. Failed lookups are never cached
either way, so recovery is immediate.

## Pluggable hooks

Defaults are registered with `TryAdd*`, so registering your own implementation **after** `AddFronteggAuth`
wins:

| Interface | Default | Purpose |
|---|---|---|
| `IUserClaimsProvider` | `FronteggUserClaimsProvider` — reads roles and permissions from the Frontegg management API | Source the user's permission/role claims. To *consume* claims rather than replace the source, use `IUserPermissionsService` instead. |
| `IPermissionIdResolver` | `DefaultPermissionIdResolver`, backed by `PermissionIdMappings` | Map a Frontegg permission key → numeric ID. |
| `IAccountStatusValidator` | `NullAccountStatusValidator` (allow-all) | Gate access on account-status claims. `ClaimBasedAccountStatusValidator` is included. |
| `IClaimsTransformer` | `NullClaimsTransformer` (no-op) | Add application-specific roles/claims after enrichment. |

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
builder.Services.AddScoped<IUserClaimsProvider, MyClaimsProvider>();
builder.Services.AddSingleton<IAccountStatusValidator, ClaimBasedAccountStatusValidator>();
```

Permission keys are tenant-defined, so this package ships no permission constants. Declare your own:

```csharp
public static class MyPermissions
{
    public const string Read = "fe.secure.read";
    public const int    ReadId = 123;
}
```

If your Frontegg application is a confidential client (requires an OIDC client secret), post-configure
`OpenIdConnectOptions` for the `Frontegg.Oidc` scheme to set one — the default configures a public client with
PKCE.

## Redis ticket store

Cookie session tickets are stored in Redis when a connection is available. Redis is resolved the first time
the ticket store is used, not while services are registered, so `AddFronteggAuth` never blocks startup on a
Redis dial and does not care whether it ran before or after your own registrations.

Resolution order:

1. **`FronteggSettings:RedisConnectionString`** — the package opens, owns, and disposes its own
   `ConnectionMultiplexer`, independent of your application's Redis even when both point at the same server
   (look for the `Frontegg:<CookieName>` client name in `CLIENT LIST`). Registered under a DI key, so it never
   collides with your own `IConnectionMultiplexer`.
2. **An `IConnectionMultiplexer` you registered** — used only when the setting above is absent, so a
   multi-instance application gets a distributed ticket store without restating its connection string. The
   borrowed connection is never disposed by this package.
3. **In-memory** — neither of the above. The store is registered so it can still be resolved, but it is
   deliberately *not* attached to the cookie: a per-process store behind a load balancer reads as a sign-in
   loop rather than as an error. The cookie stays self-contained (chunked) and validates on any instance
   sharing the Data Protection key ring; a warning is logged.

Tickets are namespaced under `authticket:<CookieName>:`, so sharing a database with application data is safe.

## Data Protection

The package always calls `AddDataProtection().SetApplicationName(DataProtectionApplicationName)` — the key
ring's discriminator, which must match across every instance serving the same cookie. Where those keys are
*stored* is yours to choose, via the `ConfigureDataProtection` callback:

```csharp
builder.Services.AddFronteggAuth(builder.Configuration, options =>
{
    options.ConfigureDataProtection = dp => dp.PersistKeysToAzureBlobStorage(blobUri, credential);
});
```

Left unset, keys stay at the ASP.NET Core default (the local file system), which is per-instance — fine for a
single process, a sign-in loop behind a load balancer. The package itself depends on no persistence provider.

For AWS Systems Manager Parameter Store, install the companion package
[`FronteggAuth.AspNetCore.DataProtection.Aws`](https://www.nuget.org/packages/FronteggAuth.AspNetCore.DataProtection.Aws):

```csharp
options.PersistDataProtectionKeysToSsm("/myapp/{environment}/dataprotection");
```

## License

MIT.
