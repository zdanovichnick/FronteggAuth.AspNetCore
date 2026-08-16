using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Helpers;
using FronteggAuth.AspNetCore.Models;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>
/// <see cref="IUserPermissionsService"/> that projects the claims from <see cref="IUserClaimsProvider"/> into a
/// <see cref="UserPermissions"/>. It adds no data path of its own — whichever provider is registered decides
/// where the claims come from, how long they are cached, and whether a failure throws.
/// </summary>
internal sealed class UserPermissionsService(
    IUserClaimsProvider claimsProvider,
    IOptions<FronteggSettings> options) : IUserPermissionsService
{
    private readonly FronteggClaimTypeOptions _claims = options.Value.ClaimTypeNames;

    public async Task<UserPermissions> GetPermissionsAsync(
        string userId,
        string companyId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(companyId);

        // Deliberately unguarded: a provider failure must surface as an exception, not as an empty permission
        // set that a caller cannot tell apart from a user who genuinely has no permissions.
        var claims = await claimsProvider.GetUserClaimsAsync(userId, companyId, cancellationToken);

        // Claim-type names are read from configuration rather than hardcoded so a host that renames them
        // (FronteggClaimTypeOptions) keeps working — the reason this projection lives in the package.
        return new UserPermissions(
            ClaimHelper.GetPermissionKeys(claims, _claims.Permissions),
            ClaimHelper.GetPermissionIds(claims, _claims.PermissionIds),
            ClaimHelper.GetRoleKeys(claims, _claims.Role));
    }
}
