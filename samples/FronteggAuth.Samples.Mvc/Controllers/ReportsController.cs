using FronteggAuth.AspNetCore.Authorization;
using FronteggAuth.AspNetCore.Models;
using FronteggAuth.Samples.Mvc.Models;
using Microsoft.AspNetCore.Mvc;

namespace FronteggAuth.Samples.Mvc.Controllers;

/// <summary>
/// Every gate the attribute surface offers, one per action. The attributes are <c>IAuthorizationFilter</c>s, so
/// they run only in the MVC action pipeline — the same class attached to a Blazor component or a minimal-API
/// endpoint would be ignored silently. Use the <c>perm:</c> / <c>permid:</c> policies there instead.
/// </summary>
/// <remarks>
/// The class-level attribute applies to every action below, so each one is really "read AND whatever the method
/// declares". A denial produces a 403 with an RFC 7807 body rather than a redirect to a login page, because by
/// the time a filter runs the user is authenticated — they are just not allowed.
/// </remarks>
[PermissionAuthorize(SamplePermissions.ReportsRead)]
public sealed class ReportsController : Controller
{
    /// <summary>Gated by the controller-level permission alone.</summary>
    public IActionResult Index() => View("Result", new GateResult(
        Action: "Reports/Index",
        Gate: $"[PermissionAuthorize(\"{SamplePermissions.ReportsRead}\")] on the controller",
        Explanation: "You hold the read permission. Every other action here requires this one as well."));

    /// <summary>
    /// Stacked attributes are ANDed: the controller's read permission and this action's write permission must
    /// both be held. Passing two keys to one attribute would instead mean OR.
    /// </summary>
    [PermissionAuthorize(SamplePermissions.ReportsWrite)]
    public IActionResult Create() => View("Result", new GateResult(
        Action: "Reports/Create",
        Gate: $"controller read + [PermissionAuthorize(\"{SamplePermissions.ReportsWrite}\")]",
        Explanation: "Attributes stack as AND because AllowMultiple is set and each instance is evaluated on its own. "
                   + $"For OR, pass several keys to one attribute: [PermissionAuthorize(\"a\", \"b\")]."));

    /// <summary>
    /// The numeric form of the same idea. It only resolves because appsettings.json maps the id to a permission
    /// key; with no mapping the numeric claim is never emitted and this denies for a reason that looks identical
    /// to a genuinely missing permission.
    /// </summary>
    [PermissionIdAuthorize(SamplePermissions.ReportsExportId)]
    public IActionResult Export() => View("Result", new GateResult(
        Action: "Reports/Export",
        Gate: $"controller read + [PermissionIdAuthorize({SamplePermissions.ReportsExportId})]",
        Explanation: $"Id {SamplePermissions.ReportsExportId} maps to {SamplePermissions.ReportsExport} via "
                   + "FronteggSettings:PermissionIdMappings. Prefer the key form in new code."));

    /// <summary>
    /// Reverse permissions deny rather than grant. Note the array literal: a collection expression is not a
    /// valid attribute argument, so this has to be <c>new[] { … }</c>.
    /// </summary>
    /// <remarks>
    /// This has no equivalent in the policy form — <c>perm:</c> policies only ever grant. If you need a denial
    /// rule outside MVC, write it as an <c>IAuthorizationRequirement</c> of your own.
    /// </remarks>
    [PermissionAuthorize(ReversePermissions = new[] { SamplePermissions.SandboxedAccount })]
    public IActionResult Restricted() => View("Result", new GateResult(
        Action: "Reports/Restricted",
        Gate: $"controller read + [PermissionAuthorize(ReversePermissions = new[] {{ \"{SamplePermissions.SandboxedAccount}\" }})]",
        Explanation: "You do NOT hold the sandbox permission, which is what let you through. Reverse permissions "
                   + "exist only on the attributes; there is no policy equivalent."));

    /// <summary>Roles rather than permissions. Matches against the configured role claim type.</summary>
    [RoleAuthorize(FronteggRoles.Admin, SampleClaimsTransformer.ReportsManagerRole)]
    public IActionResult Manage() => View("Result", new GateResult(
        Action: "Reports/Manage",
        Gate: $"controller read + [RoleAuthorize(\"{FronteggRoles.Admin}\", \"{SampleClaimsTransformer.ReportsManagerRole}\")]",
        Explanation: $"'{SampleClaimsTransformer.ReportsManagerRole}' is not a role your tenant issues — the sample's "
                   + "IClaimsTransformer derives it from the write permission. That is how a product concept enters "
                   + "without a change in the package."));

    /// <summary>
    /// Opts out of the package's filters, including the controller-level one, while still requiring an
    /// authenticated user — unlike <c>[AllowAnonymous]</c>, which would also switch off the gating middleware.
    /// </summary>
    [SkipAuth]
    public IActionResult Help() => View("Result", new GateResult(
        Action: "Reports/Help",
        Gate: "[SkipAuth]",
        Explanation: "The controller's permission filter did not run here. You are still signed in: the gating "
                   + "middleware challenged you before any filter was reached. [AllowAnonymous] would have skipped "
                   + "that too, and this page would render for a signed-out visitor."));
}
