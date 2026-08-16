using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Looks up any user's permissions and roles by id, independently of the current request principal.
/// A thin projection over <see cref="IUserClaimsProvider"/> that saves callers from knowing the
/// (configurable) claim-type names carrying permissions or how their values are encoded.
/// </summary>
/// <remarks>
/// For the <em>current</em> request's user, use <see cref="IIdentityUserService.GetUserAsync"/> instead and read
/// <see cref="ApplicationUser.Permissions"/> / <see cref="ApplicationUser.PermissionIds"/> — it reuses the
/// claims already on the principal rather than issuing a lookup.
/// </remarks>
public interface IUserPermissionsService
{
    /// <summary>
    /// Returns the permissions and roles held by <paramref name="userId"/> within
    /// <paramref name="companyId"/> (tenant).
    /// </summary>
    /// <param name="userId">The user identifier. Required.</param>
    /// <param name="companyId">The tenant/company identifier. Required.</param>
    /// <param name="cancellationToken">Cancels the underlying lookup.</param>
    /// <remarks>
    /// <para>
    /// <b>Failures propagate.</b> The default claims provider throws when the permissions endpoint returns a
    /// non-success status or is unconfigured. That is deliberate: an empty result would be indistinguishable
    /// from "this user has no permissions", which hides an outage and can widen access for a caller whose
    /// check is inverted. Handle the exception rather than treating an error as an empty permission set.
    /// </para>
    /// <para>
    /// <b>Results are cached.</b> The claims provider caches per user+tenant for
    /// <see cref="Configuration.FronteggSettings.ClaimsCacheDurationSeconds"/>, so repeat calls are cheap but
    /// may lag a permission change by up to that window. There is no invalidation hook.
    /// </para>
    /// <para>
    /// <b><see cref="UserPermissions.PermissionIds"/> depends on the provider.</b> The registered default reads
    /// the numeric IDs straight from the internal permissions endpoint. The Frontegg-API provider emits them only
    /// for keys that <see cref="IPermissionIdResolver"/> maps, so an unmapped key yields a native key with no
    /// numeric ID.
    /// </para>
    /// <para>
    /// <b>A consumer-supplied provider is honoured.</b> This service composes <see cref="IUserClaimsProvider"/>,
    /// so registering your own provider after <c>AddFronteggAuth</c> also changes what this method returns.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// <paramref name="userId"/> or <paramref name="companyId"/> is null, empty, or whitespace.
    /// </exception>
    Task<UserPermissions> GetPermissionsAsync(
        string userId,
        string companyId,
        CancellationToken cancellationToken = default);
}
