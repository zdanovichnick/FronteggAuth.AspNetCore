using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.Samples.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// FronteggSettings:ApiKey is a vendor secret. Keep it in user-secrets locally and in a secrets manager
// everywhere else; appsettings.json here holds only the non-secret half of the configuration.
builder.Configuration.AddUserSecrets<Program>(optional: true);

builder.Services.AddFronteggAuth(builder.Configuration, settings =>
{
    // A token-only host. No browser reaches this API, so there is no session to keep and nothing to sign in
    // interactively. Turning both off drops the cookie handler, the OIDC handler, the ticket store and the
    // /signin-oidc callback — and, more visibly, makes an unauthenticated request fail with 401 instead of
    // redirecting to Frontegg, which is the difference between a readable API error and an HTML login page
    // arriving in an HTTP client.
    settings.EnableCookie = false;
    settings.EnableOpenIdConnect = false;

    // Both token styles stay on. `Authorization: Bearer <jwt>` covers user and machine-to-machine access
    // tokens; the X-API-KEY header covers long-lived Frontegg API keys, which are validated by a second
    // bearer handler that ignores token lifetime and checks revocation against Frontegg on every request.
    // The smart scheme router picks between them per request, by header.
    settings.EnableJwtBearer = true;
    settings.EnableApiKey = true;
});

// The package's gating middleware rejects an unauthenticated request with a bodyless 401. These two turn
// that — and any unhandled exception — into an RFC 7807 problem document, which is what an API client
// wants to see. Both must sit ahead of UseFronteggAuth to wrap it.
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

app.UseRouting();

// UseAuthentication -> gating -> claims enrichment -> UseAuthorization, in that order. After UseRouting so the
// gating middleware can see which endpoint matched, and before the endpoints themselves.
app.UseFronteggAuth();

app.MapDiagnosticsEndpoints();
app.MapReportEndpoints();

await app.RunAsync();

/// <summary>Assembly marker so <c>AddUserSecrets</c> and <c>WebApplicationFactory</c> have a type to anchor to.</summary>
public partial class Program { }
