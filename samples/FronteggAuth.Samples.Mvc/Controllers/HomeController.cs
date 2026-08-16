using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FronteggAuth.Samples.Mvc.Controllers;

/// <summary>The public landing page and the signed-in profile page.</summary>
public sealed class HomeController(IIdentityUserService identityUserService) : Controller
{
    /// <summary>
    /// The one page a signed-out visitor can reach. AllowAnonymous is required, not optional: the package's
    /// gating middleware challenges any matched endpoint that lacks it, before authorization runs, so "no
    /// attribute" means "signed-in users only" rather than "public".
    /// </summary>
    [AllowAnonymous]
    public IActionResult Index() => View();

    /// <summary>
    /// Requires an authenticated user by virtue of carrying no opt-out, and shows what the package made of the
    /// principal.
    /// </summary>
    public async Task<IActionResult> Profile(CancellationToken cancellationToken)
    {
        // GetUserAsync rather than the User property: User projects only what is already on the principal, while
        // GetUserAsync back-fills roles and permissions from the claims provider when the enrichment middleware
        // was skipped for this request.
        var user = await identityUserService.GetUserAsync(cancellationToken);

        return View(user ?? new ApplicationUser());
    }
}
