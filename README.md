# FronteggAuth for ASP.NET Core

[Frontegg CIAM](https://developers.frontegg.com/ciam/api/overview) authentication and authorization for
ASP.NET Core — OpenID Connect, JWT bearer, and API keys behind one smart scheme router, wired up by a single
`AddFronteggAuth` call.

```csharp
builder.Services.AddFronteggAuth(builder.Configuration);
…
app.UseFronteggAuth();
```

**→ [Getting started](docs/getting-started.md)** — install, configure, and wire it into an API, an MVC app, or a
Blazor app, with the gotchas that cost the most time.

**→ [Package documentation](src/FronteggAuth.AspNetCore/README.md)** — configuration, the three authorization
surfaces, the pluggable hooks, the Redis ticket store, and Data Protection.

**→ [Samples](samples/README.md)** — three runnable hosts, one per host type.

**→ [Design notes](docs/architecture.md)** — why the scheme router, the pipeline order, and the failure-recovery
paths look the way they do.

## Packages

| Package | What it is |
|---|---|
| [`FronteggAuth.AspNetCore`](src/FronteggAuth.AspNetCore/README.md) | The integration. No AWS, Azure, or other cloud dependency. |
| [`FronteggAuth.AspNetCore.DataProtection.Aws`](src/FronteggAuth.AspNetCore.DataProtection.Aws/README.md) | Optional. Persists the Data Protection key ring to AWS SSM Parameter Store. |

Both target `net8.0`, `net9.0`, and `net10.0`.

```bash
dotnet add package FronteggAuth.AspNetCore
```

## Repository layout

```
src/       the two packages
tests/     xUnit suite, run against every target framework
samples/   three runnable hosts: Web API, MVC, Blazor
docs/      getting-started guide, design notes, and diagrams
```

## Build and test

Requires the .NET 10 SDK, plus the .NET 8 and .NET 9 SDKs to build and run the other two target frameworks.

```bash
dotnet build FronteggAuth.AspNetCore.slnx
dotnet test  FronteggAuth.AspNetCore.slnx

# one target framework
dotnet test FronteggAuth.AspNetCore.slnx -f net8.0

# one test class
dotnet test FronteggAuth.AspNetCore.slnx --filter "FullyQualifiedName~TicketStoreRegistrationTests"
```

## Samples

Three runnable hosts, one per host type. Each one is wired the way that host type actually wants to be wired,
and each README explains the choices rather than just listing them.

| Sample | Read it for |
|---|---|
| [Web API](samples/FronteggAuth.Samples.Api) | Token-only wiring (no cookies, no OIDC), `Bearer` vs `X-API-KEY`, policies on minimal-API endpoints, diagnosing a denial |
| [MVC](samples/FronteggAuth.Samples.Mvc) | The attribute surface, reverse permissions, `IClaimsTransformer`, global filters |
| [Blazor](samples/FronteggAuth.Samples.Blazor) | `AuthorizeRouteView`, `<AuthorizeView>`, `AuthenticationStateProvider` vs `IIdentityUserService` |

```bash
cd samples/FronteggAuth.Samples.Api
dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
dotnet run
```

Fill in `ClientId` and `Authority` in each sample's `appsettings.json`; keep credentials in user-secrets. See
[samples/README.md](samples/README.md) for which host type to start from and which authorization surface works
where.

## Releasing

Tag a commit `v<semver>`; the release workflow builds, tests across all three target frameworks, packs, and
pushes to nuget.org. The tag is the only place the published version comes from.

## License

MIT — see [LICENSE](LICENSE).
