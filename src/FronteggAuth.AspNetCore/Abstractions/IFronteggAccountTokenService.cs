namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>Provides a cached Frontegg tenant (account-scoped) access token.</summary>
public interface IFronteggAccountTokenService
{
    /// <summary>Returns a valid tenant token, refreshing it from Frontegg when expired.</summary>
    Task<string> GetTenantTokenAsync(CancellationToken cancellationToken = default);
}
