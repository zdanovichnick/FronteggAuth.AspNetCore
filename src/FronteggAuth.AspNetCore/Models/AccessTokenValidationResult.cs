namespace FronteggAuth.AspNetCore.Models;

/// <summary>Result of validating a Frontegg API-key / access token against the vendor-only endpoints.</summary>
public sealed class AccessTokenValidationResult
{
    /// <summary>Whether the token is valid (found and active).</summary>
    public bool IsValid { get; init; }

    /// <summary>Tenant the token belongs to.</summary>
    public string? TenantId { get; init; }

    /// <summary>User the token authenticates (user token), or the token creator (tenant token).</summary>
    public string? UserId { get; init; }

    /// <summary>User who created the token.</summary>
    public string? CreatedByUserId { get; init; }

    /// <summary>Role keys attached to the token.</summary>
    public string[]? Roles { get; init; }

    /// <summary>Human-readable token description.</summary>
    public string? Description { get; init; }
}
