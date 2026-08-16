namespace FronteggAuth.AspNetCore.Models;

/// <summary>Minimal user identity tuple (user id + tenant/company id).</summary>
public sealed record UserData(string? UserId, string? CompanyId)
{
    /// <summary>Whether a user id is present.</summary>
    public bool HasUser => !string.IsNullOrEmpty(UserId);
}
