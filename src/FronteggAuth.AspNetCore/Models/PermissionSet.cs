namespace FronteggAuth.AspNetCore.Models;

/// <summary>
/// A user's permissions in both representations: native Frontegg string keys
/// (<paramref name="Permissions"/>) and numeric IDs (<paramref name="PermissionIds"/>).
/// </summary>
public sealed record PermissionSet(string[] Permissions, int[] PermissionIds)
{
    // See UserPermissions: the compiler-generated equality for an array member is reference equality, which
    // would make two sets holding identical permissions compare unequal.
    /// <inheritdoc />
    public bool Equals(PermissionSet? other) =>
        other is not null
        && Permissions.SequenceEqual(other.Permissions)
        && PermissionIds.SequenceEqual(other.PermissionIds);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach (var permission in Permissions)
            hash.Add(permission);
        foreach (var id in PermissionIds)
            hash.Add(id);

        return hash.ToHashCode();
    }
}
