using System.Security.Claims;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Resolves the additional claims (roles and permissions) for an authenticated user within a tenant.
/// The default implementation reads from the Frontegg CIAM API; replace it to source claims elsewhere
/// (for example an internal permissions endpoint).
/// </summary>
public interface IUserClaimsProvider
{
    /// <summary>Returns the claims for <paramref name="userId"/> within <paramref name="companyId"/> (tenant).</summary>
    Task<List<Claim>> GetUserClaimsAsync(string userId, string companyId, CancellationToken cancellationToken = default);
}
