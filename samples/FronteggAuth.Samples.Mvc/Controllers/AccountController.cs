using FronteggAuth.AspNetCore.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FronteggAuth.Samples.Mvc.Controllers;

/// <summary>Explicit sign-in and sign-out, for the times a user wants to choose rather than be redirected.</summary>
public sealed class AccountController : Controller
{
    /// <summary>
    /// Starts the interactive flow deliberately. Most of the time you never write this: reaching any gated page
    /// signed-out produces the same challenge automatically. It is here for a "Sign in" button on a page that is
    /// itself anonymous.
    /// </summary>
    [AllowAnonymous]
    public IActionResult Login(string returnUrl = "/") =>
        Challenge(new AuthenticationProperties { RedirectUri = Url.IsLocalUrl(returnUrl) ? returnUrl : "/" },
            FronteggAuthSchemes.OpenIdConnect);

    /// <summary>
    /// Sign-out is two calls and both are required. The first clears the local cookie; without the second the
    /// Frontegg session survives, so the next sign-in completes silently and it looks like nothing happened.
    /// The second redirects the browser to Frontegg's end-session endpoint, which returns to
    /// <c>FronteggSettings:PostLogoutRedirectUri</c>.
    /// </summary>
    [AllowAnonymous]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(FronteggAuthSchemes.OpenIdConnect);

        // The OIDC handler has already written the redirect to Frontegg; returning EmptyResult leaves it intact.
        return new EmptyResult();
    }
}
