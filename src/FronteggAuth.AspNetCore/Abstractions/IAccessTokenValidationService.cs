using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>Validates a Frontegg API-key / access token against the vendor-only introspection endpoints.</summary>
public interface IAccessTokenValidationService
{
    /// <summary>
    /// Validates the supplied access-token id, returning tenant/user/role metadata when valid,
    /// or <c>null</c> when the token is unknown, revoked, or inactive.
    /// </summary>
    Task<AccessTokenValidationResult?> ValidateAccessTokenAsync(string accessTokenId, CancellationToken cancellationToken = default);
}
