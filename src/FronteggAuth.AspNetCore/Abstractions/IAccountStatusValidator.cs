using System.Security.Claims;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Decides whether a principal's account status permits access (e.g. active, approved, not locked out).
/// The default implementation always allows; supply a custom implementation to enforce product-specific
/// account-status rules without coupling the core package to them.
/// </summary>
public interface IAccountStatusValidator
{
    /// <summary>Returns <c>true</c> when the account status allows access.</summary>
    bool HasAccess(IReadOnlyCollection<Claim> claims);
}
