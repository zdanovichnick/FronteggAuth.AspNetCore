using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>
/// Optional <see cref="IAccountStatusValidator"/> that gates access on the boolean status claims configured in
/// <see cref="FronteggClaimTypeOptions.AccountStatusClaims"/> (with <see cref="FronteggClaimTypeOptions.InvertedStatusClaims"/>
/// inverting selected flags). Register it explicitly to replace the default allow-all validator.
/// </summary>
public sealed class ClaimBasedAccountStatusValidator(IOptions<FronteggSettings> options) : IAccountStatusValidator
{
    /// <inheritdoc />
    public bool HasAccess(IReadOnlyCollection<Claim> claims)
    {
        var names = options.Value.ClaimTypeNames;
        return ClaimHelper.HasAccess(names.AccountStatusClaims, claims, names.InvertedStatusClaims);
    }
}
