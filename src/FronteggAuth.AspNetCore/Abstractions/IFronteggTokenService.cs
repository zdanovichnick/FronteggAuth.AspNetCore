namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>Provides a cached Frontegg vendor (machine-to-machine) access token.</summary>
public interface IFronteggTokenService
{
    /// <summary>Returns a valid vendor token, refreshing it from Frontegg when expired.</summary>
    Task<string> GetVendorTokenAsync(CancellationToken cancellationToken = default);
}
