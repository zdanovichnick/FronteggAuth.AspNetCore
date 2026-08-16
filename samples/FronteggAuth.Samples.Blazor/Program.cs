using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Extensions;
using FronteggAuth.Samples.Blazor.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// FronteggSettings carries credentials (ApiKey, TenantSecret), so those belong in user-secrets or the
// environment — never in the committed appsettings.json, which holds only the non-secret half. From this
// directory:
//   dotnet user-secrets set "FronteggSettings:ApiKey" "<your vendor client secret>"
builder.Configuration.AddUserSecrets<Program>(optional: true);

// The whole integration: smart scheme router (cookie/OIDC for browsers, JWT bearer and API key for
// machines), the permission handlers, the dynamic policy provider, and the pluggable hook defaults.
builder.Services.AddFronteggAuth(builder.Configuration);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Flows the authentication state into every component, so <AuthorizeView> and [Authorize] work without
// each page fetching it. Blazor needs this even though the package has already authenticated the request.
builder.Services.AddCascadingAuthenticationState();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

var app = builder.Build();

app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseRouting();
// UseAuthentication -> gating middleware -> claims enrichment -> UseAuthorization, in that order. It has to
// sit after UseRouting so the gating middleware can see which endpoint was matched, and before the endpoints.
app.UseFronteggAuth();
app.UseAntiforgery();

app.MapStaticAssets();

// Sign-out is two steps and both are required: clearing the local cookie leaves the Frontegg session intact,
// so the next login would complete silently and look like the sign-out did nothing. The second call redirects
// the browser to Frontegg's end-session endpoint, which returns to FronteggSettings:PostLogoutRedirectUri.
app.MapGet("/account/logout", async (HttpContext httpContext) =>
{
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await httpContext.SignOutAsync(FronteggAuthSchemes.OpenIdConnect);
});

// No RequireAuthorization here: the package's gating middleware already challenges an unauthenticated browser
// request to any matched, non-anonymous endpoint, so the whole app sits behind interactive login. Page-level
// [Authorize(Policy = "perm:...")] then refines that into permission checks, which AuthorizeRouteView renders
// as a message rather than as another redirect.
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();

/// <summary>Assembly marker so <c>AddUserSecrets</c> and <c>WebApplicationFactory</c> have a type to anchor to.</summary>
public partial class Program { }
