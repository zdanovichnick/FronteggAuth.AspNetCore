namespace FronteggAuth.AspNetCore.Models;

/// <summary>
/// Conventional role keys recognised by this package. Frontegg role keys are tenant-defined, so these are
/// defaults rather than a closed set — everything that reads them compares case-insensitively, and every
/// behaviour they drive is configurable (<see cref="Configuration.FronteggSettings.BypassRoles"/>,
/// <see cref="Configuration.FronteggClaimTypeOptions.Role"/>). Declare your own constants for
/// product-specific roles; nothing here has to exist in your tenant.
/// </summary>
public static class FronteggRoles
{
    /// <summary>Tenant administrator. Surfaces as <see cref="ApplicationUser.IsAdmin"/>.</summary>
    public const string Admin = "admin";

    /// <summary>Ordinary authenticated end user.</summary>
    public const string User = "user";

    /// <summary>Administrator of a single account/tenant, as distinct from a vendor-wide administrator.</summary>
    public const string AccountAdmin = "accountAdmin";

    /// <summary>Vendor-wide administrator spanning every tenant.</summary>
    public const string SuperAdmin = "superAdmin";

    /// <summary>
    /// Machine/service identity. Bypasses permission checks by default — see
    /// <see cref="Configuration.FronteggSettings.BypassRoles"/>. Surfaces as
    /// <see cref="ApplicationUser.IsSystemUser"/>.
    /// </summary>
    public const string System = "system";

    /// <summary>
    /// Non-interactive API caller. Surfaces as <see cref="ApplicationUser.IsSystemUser"/> alongside
    /// <see cref="System"/>, but is <em>not</em> a permission-bypass role by default.
    /// </summary>
    public const string Api = "api";
}
