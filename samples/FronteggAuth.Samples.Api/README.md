# Web API sample

A minimal-API host with no browser surface at all: no cookies, no OpenID Connect, no login page.

Read this one for: **token-only hosts, the `Bearer` vs `X-API-KEY` split, gating minimal-API endpoints with
`perm:` / `permid:` policies, and diagnosing a denial.**

## Run it

```bash
dotnet run
```

Set `ClientId`, `Authority` and `ApiBaseUrl` in [appsettings.json](appsettings.json) first. Nothing here needs
a redirect URI registered in Frontegg — this host never starts an interactive flow.

Then send requests with [FronteggAuth.Samples.Api.http](FronteggAuth.Samples.Api.http), which has a slot for a
bearer token and one for an API key.

| Endpoint | Gate |
|---|---|
| `GET /api/ping` | `AllowAnonymous` |
| `GET /api/reports` | `perm:sample.reports.read` |
| `DELETE /api/reports/{id}` | `permid:101` |
| `GET /api/reports/admin-summary` | role `admin` |
| `GET /api/diagnostics/me` | authenticated |
| `GET /api/diagnostics/claims` | authenticated |
| `GET /api/diagnostics/permission?key=…` | authenticated — probes any permission key |
| `GET /api/diagnostics/permission-id/{id}` | authenticated — probes any permission id |
| `GET /api/diagnostics/tenant-token` | authenticated — pre-flights the client-credentials token |

## What this sample is demonstrating

### Turning the browser half off

```csharp
settings.EnableCookie = false;
settings.EnableOpenIdConnect = false;
```

This is the one switch that matters for an API. It drops the cookie handler, the OIDC handler, the session
ticket store and the `/signin-oidc` callback — and it changes what an unauthenticated request gets back. With
OIDC enabled, a request whose `Accept` header mentions `text/html` is redirected to Frontegg; a client that
happens to send a browser-ish `Accept` then receives a login page instead of an error. With it disabled every
unauthenticated request to a gated endpoint gets a flat 401.

There is still a Redis-backed ticket store in the package, but it only ever attaches to a cookie, so a
token-only host needs no Redis.

### `AllowAnonymous` is required, not optional

`/api/ping` carries `.AllowAnonymous()`. Without it the endpoint is gated, because the package's middleware
rejects any *matched* endpoint that lacks anonymous metadata — before the authorization middleware runs.
Attaching no policy does not make an endpoint public.

The practical consequence: you cannot express "public" by omission here, and you do not need a fallback policy
to express "everything else is private". That is already the default.

### Two token styles, one router

The smart scheme router picks a handler per request, by header:

| Request carries | Handler | Notes |
|---|---|---|
| `X-API-KEY: …` | `Frontegg.ApiKey` | Lifetime **not** validated; revocation checked against Frontegg on every request |
| `Authorization: Bearer …` | `Bearer` | Ordinary access-token validation |
| neither | `Cookies` | Not registered in this sample, so this path 401s |

`GET /api/diagnostics/me` reports which one ran, under `credential.scheme`. If a token you believe is valid is
rejected, check that first — an API key sent in the `Authorization` header takes the ordinary bearer path and
fails on expiry.

The API-key handler revalidates against Frontegg's introspection endpoint on every request rather than trusting
the claims already in the token. That is deliberate: API keys are long-lived, so a cached "already validated"
answer would let a revoked key keep working.

### Gating minimal-API endpoints

```csharp
reports.MapGet("/", …).RequireAuthorization("perm:sample.reports.read");
reports.MapDelete("/{id:int}", …).RequireAuthorization("permid:101");
reports.MapGet("/admin-summary", …).RequireAuthorization(policy => policy.RequireRole(FronteggRoles.Admin));
```

Neither policy is registered anywhere — `FronteggPolicyProvider` materializes any name starting with `perm:`
or `permid:` on demand. Add a permission in the Frontegg portal and it is usable the moment you reference it.

The attribute forms (`[PermissionAuthorize]`, `[PermissionIdAuthorize]`) would do nothing here: they are
`IAuthorizationFilter`s, which only the MVC action pipeline runs. See the [MVC sample](../FronteggAuth.Samples.Mvc)
for those, and for the reverse-permission behaviour that only the attributes have.

### `permid:` only works when the id is mapped

```json
"PermissionIdMappings": { "101": "sample.reports.delete" }
```

The numeric permission claim is emitted by the claims provider from this map. With no entry for an id, the
claim never appears and every `permid:` gate on it denies — which looks exactly like a user missing the
permission. `GET /api/diagnostics/permission-id/101` returns `mapsToKey`, so you can tell the two apart.

### Diagnosing a denial

The probe endpoints evaluate a policy *without being gated by it*, so they answer 200 with `granted: true|false`
rather than 403. That separates three failures that otherwise look alike:

- **401** — no credential, or the credential failed validation. Nothing to do with permissions.
- **`granted: false`** — authenticated, permission genuinely absent. Check `/api/diagnostics/claims`.
- **`granted: false` with `mapsToKey: null`** — the id is not mapped; the permission may well be present.

### Errors come back as `ProblemDetails`

The package returns a bodyless 401. `AddProblemDetails()` plus `UseStatusCodePages()` — both ahead of
`UseFronteggAuth()` — turn that into RFC 7807 JSON, which is what an API client expects. This is host wiring,
not something the package does for you.

## See also

- [Getting started](../../docs/getting-started.md) — the full configuration and usage guide
- [MVC sample](../FronteggAuth.Samples.Mvc) — the attribute surface and interactive login
- [Blazor sample](../FronteggAuth.Samples.Blazor) — cookie/OIDC login and `<AuthorizeView>`
