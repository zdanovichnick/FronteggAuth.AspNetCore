using System.Security.Claims;

namespace FronteggAuth.AspNetCore.Configuration;

/// <summary>
/// Configurable claim-type names. Defaults target a standard Frontegg-issued principal,
/// but every name can be overridden so the package stays product-neutral.
/// </summary>
public sealed class FronteggClaimTypeOptions
{
    /// <summary>Claim carrying the unique user identifier. Default <c>sub</c>.</summary>
    public string UserId { get; set; } = "sub";

    /// <summary>Claim carrying the user's email address.</summary>
    public string Email { get; set; } = "email";

    /// <summary>Claim carrying the user's display name.</summary>
    public string Name { get; set; } = "name";

    /// <summary>Claim carrying the user's first name.</summary>
    public string FirstName { get; set; } = "firstName";

    /// <summary>Claim carrying the user's last name.</summary>
    public string LastName { get; set; } = "lastName";

    /// <summary>Claim carrying the tenant/account identifier. Default <c>tenantId</c>.</summary>
    public string TenantId { get; set; } = "tenantId";

    /// <summary>Claim carrying the company/account display name.</summary>
    public string CompanyName { get; set; } = "companyName";

    /// <summary>Claim carrying the user's department.</summary>
    public string Department { get; set; } = "Department";

    /// <summary>Claim carrying the user's profile picture URL.</summary>
    public string ProfilePictureUrl { get; set; } = "profilePictureUrl";

    /// <summary>Role claim type. Default <see cref="ClaimTypes.Role"/>.</summary>
    public string Role { get; set; } = ClaimTypes.Role;

    /// <summary>Claim carrying native Frontegg permission keys (comma-separated string keys, e.g. <c>fe.secure.read</c>).</summary>
    public string Permissions { get; set; } = "permissions";

    /// <summary>Claim carrying numeric permission IDs (comma-separated integers).</summary>
    public string PermissionIds { get; set; } = "Permission";

    /// <summary>
    /// Claim carrying the kind of token presented (e.g. <c>tenantApiToken</c>). Default <c>type</c>.
    /// Evaluated against <see cref="FronteggSettings.BypassTokenTypes"/>.
    /// </summary>
    public string TokenType { get; set; } = "type";

    /// <summary>Claim carrying the bearer access token.</summary>
    public string AccessToken { get; set; } = "access_token";

    /// <summary>Claim carrying the OIDC id token.</summary>
    public string IdToken { get; set; } = "id_token";

    /// <summary>Claim carrying the token expiry timestamp.</summary>
    public string ExpiresAt { get; set; } = "expires_at";

    /// <summary>
    /// Optional boolean account-status claims evaluated by the built-in claim-based
    /// account-status validator (when enabled). Empty by default — no status gating.
    /// </summary>
    public IList<string> AccountStatusClaims { get; set; } = [];

    /// <summary>
    /// Subset of <see cref="AccountStatusClaims"/> whose boolean meaning is inverted
    /// (i.e. <c>true</c> means "blocked", such as <c>logout</c> or <c>isPasswordExpired</c>).
    /// </summary>
    public ISet<string> InvertedStatusClaims { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}
