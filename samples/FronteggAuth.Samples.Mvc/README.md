# MVC sample

Controllers and Razor views behind Frontegg interactive login.

Read this one for: **the attribute authorization surface (`[PermissionAuthorize]`, `[PermissionIdAuthorize]`,
`[RoleAuthorize]`, `[SkipAuth]`), reverse permissions, and plugging product logic in through `IClaimsTransformer`.**

## Run it

```bash
dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
dotnet run
```

Set `ClientId` and `Authority` in [appsettings.json](appsettings.json) first, and register
`https://localhost:7211/signin-oidc` as an allowed redirect URI in the Frontegg admin portal (and
`https://localhost:7211/` as an allowed logout redirect).

| Page | Gate |
|---|---|
| `/` | `[AllowAnonymous]` — the only page a signed-out visitor reaches |
| `/Home/Profile` | authenticated |
| `/Reports/Index` | `[PermissionAuthorize("sample.reports.read")]` on the controller |
| `/Reports/Create` | controller permission **and** `sample.reports.write` |
| `/Reports/Export` | `[PermissionIdAuthorize(101)]` |
| `/Reports/Restricted` | denied if you hold `sample.account.sandboxed` |
| `/Reports/Manage` | `[RoleAuthorize("admin", "reportsManager")]` |
| `/Reports/Help` | `[SkipAuth]` — signed in, no permission check |
| `/Account/Logout` | local cookie sign-out **and** Frontegg end-session |

## What this sample is demonstrating

### The attributes only work here

`[PermissionAuthorize]` and friends are `IAuthorizationFilter`s, and only the MVC action-invocation pipeline
runs those. Attach one to a Blazor component or a minimal-API endpoint and it is ignored — silently, which is
the dangerous part. Outside MVC, use the equivalent policy names:

```csharp
[Authorize(Policy = "perm:sample.reports.read")]   // works everywhere
[PermissionAuthorize("sample.reports.read")]       // works in MVC actions only
```

The two agree because both funnel through the same bypass rule (`PermissionBypass`), so a `system`-role
principal or a `tenantApiToken` skips either one.

### AND vs OR

```csharp
[PermissionAuthorize("a", "b")]                     // OR — either key grants
[PermissionAuthorize("a")] [PermissionAuthorize("b")] // AND — each instance is evaluated independently
```

`ReportsController` uses both: the class-level attribute ANDs with whatever each action declares.

### Reverse permissions have no policy equivalent

```csharp
[PermissionAuthorize(ReversePermissions = new[] { "sample.account.sandboxed" })]
```

Holding the listed permission *denies* access. `perm:` policies only ever grant, so there is no way to express
this as a policy name — if you need a denial rule outside MVC, write your own `IAuthorizationRequirement`.

Note `new[] { … }` rather than `[…]`: a collection expression is not a valid attribute argument.

### `[SkipAuth]` is not `[AllowAnonymous]`

`[SkipAuth]` opts an action out of this package's permission and role filters while still requiring a signed-in
user — the gating middleware ran long before any filter did. `[AllowAnonymous]` switches off both, and is the
only way to make a page truly public.

### Product logic enters through a hook, not a fork

[SampleClaimsTransformer.cs](SampleClaimsTransformer.cs) derives a `reportsManager` role from the write
permission, so `[RoleAuthorize("reportsManager")]` and `User.IsInRole("reportsManager")` work for a concept the
tenant only expresses as a permission.

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
builder.Services.AddSingleton<IClaimsTransformer, SampleClaimsTransformer>();  // after, on purpose
```

The package registers its hook defaults with `TryAdd*`, so registering afterwards wins. The other three hooks
are `IUserClaimsProvider`, `IPermissionIdResolver` and `IAccountStatusValidator`.

Two details in that transformer are worth copying: it reads the permission claim under
`ClaimTypeNames.Permissions` rather than a hardcoded `"permissions"`, and it writes the role under
`identity.RoleClaimType` rather than `ClaimTypes.Role` — `IsInRole` only reads the type the identity declares,
and the package points it at whatever `FronteggSettings:ClaimTypeNames:Role` says.

### Applying a gate globally

Everything above is per-controller. The same attributes work as MVC global filters when a baseline applies to
the whole app:

```csharp
builder.Services.AddControllersWithViews(options =>
    options.Filters.Add(new PermissionAuthorizeAttribute("sample.portal.access")));
```

`[AllowAnonymous]` and `[SkipAuth]` still opt individual actions out, so the escape hatches keep working.

### Denials are 403, not a redirect

A filter denial returns 403 with an RFC 7807 body rather than bouncing to a login page — by the time a filter
runs, the user is authenticated and simply not permitted. Re-challenging them would loop. If you want a styled
"access denied" page, handle 403 in the host (`UseStatusCodePagesWithReExecute`).

### Sign-out is two calls

```csharp
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
await HttpContext.SignOutAsync(FronteggAuthSchemes.OpenIdConnect);
```

The first clears the local session. Without the second, the Frontegg session survives and the next sign-in
completes silently — which looks exactly like sign-out not working.

## See also

- [Getting started](../../docs/getting-started.md) — the full configuration and usage guide
- [API sample](../FronteggAuth.Samples.Api) — token-only host, no cookies
- [Blazor sample](../FronteggAuth.Samples.Blazor) — `AuthorizeRouteView` and `<AuthorizeView>`
