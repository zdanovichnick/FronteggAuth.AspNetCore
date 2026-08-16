namespace FronteggAuth.AspNetCore.Models;

/// <summary>
/// A user's authorization data resolved for a single tenant. Permissions appear in both representations —
/// native Frontegg keys and numeric IDs — because the two authorization surfaces
/// (<c>[PermissionAuthorize]</c> and <c>[PermissionIdAuthorize]</c>) read different ones.
/// </summary>
/// <param name="Permissions">Native Frontegg permission keys (e.g. <c>fe.secure.read</c>).</param>
/// <param name="PermissionIds">
/// Numeric permission IDs. May be empty even when <paramref name="Permissions"/> is not —
/// see <see cref="Abstractions.IUserPermissionsService"/> for when they are populated.
/// </param>
/// <param name="Roles">Role keys held by the user within the tenant.</param>
public sealed record UserPermissions(string[] Permissions, int[] PermissionIds, string[] Roles)
{
    /// <summary>A user with no permissions and no roles.</summary>
    public static UserPermissions Empty { get; } = new([], [], []);

    // A record promises value equality, but the compiler-generated comparison of an array member is reference
    // equality — so two instances carrying the same permissions would compare unequal. Comparing the contents
    // keeps the promise the record keyword makes to a caller.
    /// <inheritdoc />
    public bool Equals(UserPermissions? other) =>
        other is not null
        && Permissions.SequenceEqual(other.Permissions)
        && PermissionIds.SequenceEqual(other.PermissionIds)
        && Roles.SequenceEqual(other.Roles);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach (var permission in Permissions)
            hash.Add(permission);
        foreach (var id in PermissionIds)
            hash.Add(id);
        foreach (var role in Roles)
            hash.Add(role);

        return hash.ToHashCode();
    }
}
