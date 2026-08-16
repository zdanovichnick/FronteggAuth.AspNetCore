using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>
/// Dynamic <see cref="IAuthorizationPolicyProvider"/> that materializes permission policies on demand:
/// <c>[Authorize(Policy = "perm:fe.secure.read")]</c> requires a Frontegg permission key, and
/// <c>[Authorize(Policy = "permid:123")]</c> requires a numeric permission ID. All other policy names
/// fall back to the default provider.
/// </summary>
public sealed class FronteggPolicyProvider : IAuthorizationPolicyProvider
{
    /// <summary>Prefix for native Frontegg permission-key policies.</summary>
    public const string PermissionPrefix = "perm:";

    /// <summary>Prefix for numeric permission-id policies.</summary>
    public const string PermissionIdPrefix = "permid:";

    private readonly DefaultAuthorizationPolicyProvider _fallback;

    /// <summary>Creates the provider, delegating non-permission policies to the default provider.</summary>
    public FronteggPolicyProvider(IOptions<AuthorizationOptions> options) => _fallback = new DefaultAuthorizationPolicyProvider(options);

    /// <inheritdoc />
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(PermissionPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var key = policyName[PermissionPrefix.Length..];
            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddRequirements(new PermissionRequirement(key))
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        if (policyName.StartsWith(PermissionIdPrefix, StringComparison.OrdinalIgnoreCase)
            && int.TryParse(policyName[PermissionIdPrefix.Length..], out var id))
        {
            var policy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddRequirements(new PermissionIdRequirement(id))
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        return _fallback.GetPolicyAsync(policyName);
    }
}
