# Samples

Three hosts, one package. They are separate rather than combined because the interesting differences between
them *are* the lesson: the same library is wired differently for a browser app and for a token-only API, and
the authorization surface that works in one does not always work in the other.

| Sample | Host type | Read it for |
|---|---|---|
| [FronteggAuth.Samples.Api](FronteggAuth.Samples.Api) | Minimal APIs, no browser surface | Token-only wiring, `Bearer` vs `X-API-KEY`, `perm:` / `permid:` policies on endpoints, diagnosing a denial |
| [FronteggAuth.Samples.Mvc](FronteggAuth.Samples.Mvc) | Controllers + Razor views | The attribute surface, reverse permissions, `IClaimsTransformer`, global filters |
| [FronteggAuth.Samples.Blazor](FronteggAuth.Samples.Blazor) | Blazor Web App, interactive server | `AuthorizeRouteView`, `<AuthorizeView>`, `AuthenticationStateProvider` vs `IIdentityUserService` |

Start with [docs/getting-started.md](../docs/getting-started.md) for the concepts; come here for working code.

## Pick one by what you are building

- **An API that only ever sees tokens** → API sample. Turn `EnableCookie` and `EnableOpenIdConnect` off; there
  is then no session, no ticket store, and no redirect-to-login for a client that happens to send an
  HTML-ish `Accept` header.
- **A server-rendered web app** → MVC or Blazor. Leave the defaults on.
- **Both in one host** (a web app that also exposes machine endpoints) → leave the defaults on, as in the MVC
  sample. The smart scheme router already picks per request: API-key header → API-key handler, `Bearer` →
  bearer handler, otherwise the cookie.

## Which authorization surface works where

| Surface | Minimal API | MVC action | Blazor component |
|---|---|---|---|
| `[Authorize(Policy = "perm:key")]` / `RequireAuthorization("perm:key")` | ✅ | ✅ | ✅ |
| `[Authorize(Policy = "permid:123")]` | ✅ | ✅ | ✅ |
| `[PermissionAuthorize]`, `[PermissionIdAuthorize]`, `[RoleAuthorize]`, `[SkipAuth]` | ❌ | ✅ | ❌ |

The attributes are `IAuthorizationFilter`s, which only the MVC action pipeline runs. Outside MVC they are
ignored without an error — the one case where picking the wrong surface fails open. Reverse permissions
(deny-on-presence) exist only on the attributes.

## Running any of them

Each sample needs a Frontegg tenant. `ClientId`, `Authority`, `ApiBaseUrl`, and `ApiKey` are the four
**required** `FronteggSettings` keys — see [getting-started.md §3](../docs/getting-started.md#3-configure) for
those plus the full optional-key reference. Set the non-secret three in the sample's `appsettings.json`:

```json
"FronteggSettings": {
  "ClientId": "<your Frontegg client id>",
  "Authority": "https://<your-login-domain>",
  "ApiBaseUrl": "https://api.frontegg.com"
}
```

and the vendor secret (`ApiKey`) in user-secrets, never in the file:

```bash
dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
```

The two browser samples also need their redirect URIs registered in the Frontegg admin portal:

| Sample | URL | Redirect URI to allow |
|---|---|---|
| API | `https://localhost:7210` | — none, no interactive flow |
| MVC | `https://localhost:7211` | `https://localhost:7211/signin-oidc` |
| Blazor | `https://localhost:7209` | `https://localhost:7209/signin-oidc` |

The permission keys the samples gate on (`sample.reports.read` and friends) will not exist in your tenant.
Either create them, or edit each sample's `SamplePermissions` to name permissions you do have — the diagnostic
endpoints in the API sample tell you which ones the principal actually carries.
