namespace FronteggAuth.AspNetCore.Models;

/// <summary>
/// Values Frontegg stamps on the token-type claim
/// (<see cref="Configuration.FronteggClaimTypeOptions.TokenType"/>, <c>type</c> by default).
/// The claim is not part of the inbound JWT claim-type map, so it reaches the principal unrenamed
/// regardless of the handler's <c>MapInboundClaims</c> setting.
/// </summary>
public static class FronteggTokenTypes
{
    /// <summary>Account-scoped API token — a machine credential issued for a tenant rather than for a user.</summary>
    public const string TenantApiToken = "tenantApiToken";
}
