using Microsoft.AspNetCore.Authorization;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>Policy requirement satisfied when the principal holds a native Frontegg permission key.</summary>
public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    /// <summary>Required permission key.</summary>
    public string Permission { get; } = permission;
}

/// <summary>Policy requirement satisfied when the principal holds a numeric permission ID.</summary>
public sealed class PermissionIdRequirement(int permissionId) : IAuthorizationRequirement
{
    /// <summary>Required numeric permission ID.</summary>
    public int PermissionId { get; } = permissionId;
}
