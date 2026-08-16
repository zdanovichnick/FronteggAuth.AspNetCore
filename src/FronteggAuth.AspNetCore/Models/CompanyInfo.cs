namespace FronteggAuth.AspNetCore.Models;

/// <summary>Tenant/company metadata resolved from the principal.</summary>
public sealed record CompanyInfo(int CompanyId, string? CompanyName, string? Department);
