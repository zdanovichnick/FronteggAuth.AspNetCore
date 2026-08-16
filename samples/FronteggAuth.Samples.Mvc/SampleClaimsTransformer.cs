using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.Extensions.Options;

namespace FronteggAuth.Samples.Mvc;

/// <summary>
/// Derives an application role from a permission, so <c>[RoleAuthorize("reportsManager")]</c> and
/// <c>User.IsInRole(...)</c> work for a concept the tenant only expresses as a permission. This is the shape
/// product-specific logic is meant to take: a hook implementation in the application, not a change in the
/// package.
/// </summary>
/// <remarks>
/// Runs after the claims provider has enriched the principal and before the account-status validator, on every
/// request the claims-enrichment middleware handles. Keep it cheap and synchronous — it is not the place for
/// an HTTP call or a database read.
/// </remarks>
public sealed class SampleClaimsTransformer(IOptions<FronteggSettings> settings) : IClaimsTransformer
{
    /// <summary>Role granted to anyone holding <see cref="SamplePermissions.ReportsWrite"/>.</summary>
    public const string ReportsManagerRole = "reportsManager";

    private readonly FronteggSettings _settings = settings.Value;

    /// <inheritdoc />
    public void Transform(ClaimsIdentity identity)
    {
        // Read the permission claim under its configured name rather than a hardcoded "permissions": a tenant
        // that emits permissions under a different claim type stays working.
        var permissionClaimType = _settings.ClaimTypeNames.Permissions;

        var holdsWrite = identity.FindAll(permissionClaimType)
            .SelectMany(claim => claim.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Any(permission => string.Equals(permission, SamplePermissions.ReportsWrite, StringComparison.OrdinalIgnoreCase));

        if (!holdsWrite || identity.HasClaim(identity.RoleClaimType, ReportsManagerRole))
            return;

        // identity.RoleClaimType, not ClaimTypes.Role: the package points it at
        // FronteggSettings:ClaimTypeNames:Role, and IsInRole only reads the type the identity declares.
        identity.AddClaim(new Claim(identity.RoleClaimType, ReportsManagerRole));
    }
}
