using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.Samples.Mvc;

var builder = WebApplication.CreateBuilder(args);

// FronteggSettings:ApiKey is a vendor secret. Keep it in user-secrets locally and in a secrets manager
// everywhere else; appsettings.json here holds only the non-secret half of the configuration.
builder.Configuration.AddUserSecrets<Program>(optional: true);

// Defaults are what an interactive web app wants: cookie session, OIDC challenge, plus the bearer and API-key
// schemes for any endpoint this app also exposes to machines. No toggles needed.
builder.Services.AddFronteggAuth(builder.Configuration);

// Registered *after* AddFronteggAuth on purpose. The package registers its hook defaults with TryAdd, so the
// last-registered implementation of a hook wins — this is how product-specific behaviour enters without a
// change in the library. The other three hooks are IUserClaimsProvider, IPermissionIdResolver and
// IAccountStatusValidator.
builder.Services.AddSingleton<IClaimsTransformer, SampleClaimsTransformer>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseRouting();

// UseAuthentication -> gating -> claims enrichment -> UseAuthorization, in that order. After UseRouting so the
// gating middleware can see which endpoint matched, and before the endpoints themselves.
app.UseFronteggAuth();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

await app.RunAsync();

/// <summary>Assembly marker so <c>AddUserSecrets</c> and <c>WebApplicationFactory</c> have a type to anchor to.</summary>
public partial class Program { }
