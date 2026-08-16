using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>Resolves the current <see cref="ApplicationUser"/> and access token from the request principal.</summary>
public interface IIdentityUserService
{
    /// <summary>
    /// The current authenticated user projected from the request principal, or <c>null</c> when unauthenticated.
    /// Reflects only the claims already on the principal — on a request the claims-enrichment middleware skipped
    /// (an anonymous endpoint, an unmatched route, an OIDC callback) the enriched values are absent. Use
    /// <see cref="GetUserAsync"/> when those values must be present.
    /// </summary>
    ApplicationUser? User { get; }

    /// <summary>
    /// The current authenticated user, or <c>null</c> when unauthenticated. When the principal yields no company
    /// name — the marker that the claims-enrichment middleware did not run for this request — the enriched claims
    /// are fetched from <see cref="IUserClaimsProvider"/>, merged into the principal, and the user is re-projected
    /// from the merged set. The fetch runs at most once per request and is skipped entirely when the principal
    /// already carries a company name.
    /// </summary>
    Task<ApplicationUser?> GetUserAsync(CancellationToken cancellationToken = default);

    /// <summary>Returns the current request's access token (bearer header, API-key header, or stored cookie token).</summary>
    Task<string?> GetCurrentUserTokenAsync(CancellationToken cancellationToken = default);
}
