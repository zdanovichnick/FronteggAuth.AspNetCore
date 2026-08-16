# Blazor sample

A Blazor Web App (interactive server render mode) behind Frontegg interactive login.

Read this one for: **cookie + OpenID Connect login, sign-out, `<AuthorizeView>`, `AuthorizeRouteView`, and
gating a page component on a permission.**

## Run it

```bash
dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
dotnet run
```

Set `ClientId` and `Authority` in [appsettings.json](appsettings.json) first, and register
`https://localhost:7209/signin-oidc` as an allowed redirect URI in the Frontegg admin portal (and
`https://localhost:7209/` as an allowed logout redirect).

Then open <https://localhost:7209> — you are redirected to Frontegg immediately, because nothing here is
anonymous.

| Page | Shows |
|---|---|
| `/` | You got through the interactive flow |
| `/user` | The `ApplicationUser` projection, plus the raw claims behind it |
| `/reports` | A page gated on `perm:sample.reports.read` |
| `/account/logout` | Local cookie sign-out **and** Frontegg end-session |

## What this sample is demonstrating

### The whole app sits behind login, and nothing asks for it

`MapRazorComponents<App>()` carries no `RequireAuthorization()`. The redirect to Frontegg comes from the
package's gating middleware, which challenges any *matched, non-anonymous* endpoint reached by an
unauthenticated browser request. To let a page render anonymously, mark it `[AllowAnonymous]` — an
authorization policy alone will not do it, because the gate runs before authorization.

### Policies work in Blazor; the attributes do not

`[PermissionAuthorize]` and `[PermissionIdAuthorize]` are `IAuthorizationFilter`s, and only the MVC
action-invocation pipeline runs those. A Blazor component never sees them. Use policy names instead:

```razor
@attribute [Authorize(Policy = "perm:sample.reports.read")]
```

Nothing registers that policy — the package's `FronteggPolicyProvider` materializes any `perm:` or `permid:`
name on demand.

### `AuthorizeRouteView`, not `RouteView`

A page-level `[Authorize]` attribute does nothing under a plain `RouteView`; the component renders anyway.
[Routes.razor](Components/Routes.razor) uses `AuthorizeRouteView` and supplies a `NotAuthorized` fragment, so a
signed-in user missing the permission gets a message rather than a redirect loop.

### `IIdentityUserService` needs a request, `AuthenticationStateProvider` does not

[UserProfile.razor](Components/Pages/UserProfile.razor) is statically server-rendered on purpose:
`IIdentityUserService` resolves the principal through `IHttpContextAccessor`, which exists during SSR but not
inside a persistent interactive circuit. Inside an interactive component, read the cascading authentication
state (`<AuthorizeView>` or `AuthenticationStateProvider`) instead — the same page does that for the raw-claims
table, which is why that half works in either render mode.

That page also calls `GetUserAsync()` rather than reading the `User` property. `User` projects only what is
already on the principal; `GetUserAsync()` back-fills roles and permissions when the claims-enrichment
middleware was skipped for the request.

### Sign-out is two calls

```csharp
await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
await httpContext.SignOutAsync(FronteggAuthSchemes.OpenIdConnect);
```

The first clears the local session. Without the second, the Frontegg session survives and the next login
completes silently — which looks exactly like sign-out not working.

## See also

- [Getting started](../../docs/getting-started.md) — the full configuration and usage guide
- [API sample](../FronteggAuth.Samples.Api) — token-only host, no cookies
- [MVC sample](../FronteggAuth.Samples.Mvc) — the attribute surface
