namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>Provides a cached Frontegg user-scoped access token acquired via email lookup and PAT exchange.</summary>
public interface IFronteggUserTokenService
{
    /// <summary>
    /// Obtains a valid user JWT for the given email, caching it until expiry and reusing the underlying
    /// PAT (Personal Access Token) credentials across refreshes.
    /// </summary>
    /// <param name="email">The user's email address.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A valid user JWT token.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the user is not found or token exchange fails.</exception>
    Task<string> GetUserTokenAsync(string email, CancellationToken cancellationToken = default);
}
