using System.Globalization;

namespace FronteggAuth.AspNetCore.Models;

/// <summary>
/// View of the authenticated principal. Permissions are exposed in both representations:
/// <see cref="Permissions"/> holds native Frontegg permission keys; <see cref="PermissionIds"/>
/// holds numeric IDs (populated when a permission-id map/resolver is configured).
/// </summary>
public class ApplicationUser
{
    /// <summary>Creates an empty user.</summary>
    public ApplicationUser()
    {
    }

    /// <summary>Creates a populated user.</summary>
    public ApplicationUser(Guid id, string? name, string? firstName, string? lastName,
        CompanyInfo company, string? email, PermissionSet permissions,
        bool isAdmin, bool isSystemUser, string? profilePictureUrl, string[]? roles = null,
        string? vendorMetadata = null)
    {
        Id = id;
        Name = name;

        if (string.IsNullOrWhiteSpace(firstName) && string.IsNullOrWhiteSpace(lastName) && !string.IsNullOrWhiteSpace(name))
        {
            var parts = name.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            firstName = parts[0];
            lastName = parts.Length > 1 ? parts[1] : null;
        }

        FirstName = firstName;
        LastName = lastName;
        CompanyId = company.CompanyId;
        CompanyName = company.CompanyName;
        Department = company.Department;
        Email = email;
        Permissions = permissions.Permissions;
        PermissionIds = permissions.PermissionIds;
        IsAdmin = isAdmin;
        IsSystemUser = isSystemUser;
        PictureUrl = profilePictureUrl;
        Roles = roles ?? [];
        VendorMetadata = vendorMetadata;
    }

    /// <summary>Unique user identifier (parsed from the user-id claim; <see cref="Guid.Empty"/> when not a GUID).</summary>
    public Guid Id { get; }

    /// <summary>Display name.</summary>
    public string? Name { get; }

    /// <summary>First name.</summary>
    public string? FirstName { get; }

    /// <summary>Last name.</summary>
    public string? LastName { get; }

    /// <summary>Tenant/company identifier.</summary>
    public int CompanyId { get; }

    /// <summary>Company display name.</summary>
    public string? CompanyName { get; }

    /// <summary>Department.</summary>
    public string? Department { get; }

    /// <summary>Email address.</summary>
    public string? Email { get; }

    /// <summary>Profile picture URL.</summary>
    public string? PictureUrl { get; }

    /// <summary>Native Frontegg permission keys (e.g. <c>fe.secure.read</c>).</summary>
    public IReadOnlyList<string> Permissions { get; } = [];

    /// <summary>Numeric permission IDs.</summary>
    public int[] PermissionIds { get; } = [];

    /// <summary>Whether the user holds an admin role.</summary>
    public bool IsAdmin { get; }

    /// <summary>Whether the user is a system/service principal.</summary>
    public bool IsSystemUser { get; }

    /// <summary>Role keys held by the user.</summary>
    public IReadOnlyList<string> Roles { get; } = [];

    /// <summary>Vendor/account metadata resolved from the <c>vendorMetadata</c> object of the <c>customClaims</c> claim; <c>null</c> when absent.</summary>
    public string? VendorMetadata { get; }

    /// <summary>Two-letter initials, or <c>null</c> when first/last name are unavailable.</summary>
    public string? Initials
    {
        get
        {
            if (FirstName is null || LastName is null) return null;
            var first = FirstName.Trim();
            var last = LastName.Trim();
            if (first.Length == 0 || last.Length == 0) return null;
            return string.Concat(char.ToUpper(first[0]), char.ToUpper(last[0]));
        }
    }

    /// <summary>Title-cased full name.</summary>
    public string FullName
    {
        get
        {
            var fullName = $"{FirstName ?? string.Empty} {LastName ?? string.Empty}".Trim();
            return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(fullName);
        }
    }
}
