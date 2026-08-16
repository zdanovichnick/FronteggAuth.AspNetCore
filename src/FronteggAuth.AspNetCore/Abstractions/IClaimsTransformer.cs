using System.Security.Claims;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Optional hook invoked after the claims provider enriches the principal, allowing consumers to add
/// product-specific roles or claims (for example deriving an admin role from a permission). No-op by default.
/// </summary>
public interface IClaimsTransformer
{
    /// <summary>Adds or adjusts claims on the authenticated <paramref name="identity"/>.</summary>
    void Transform(ClaimsIdentity identity);
}
