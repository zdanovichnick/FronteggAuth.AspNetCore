using System.Security.Claims;
using System.Text.Json;
using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.AspNetCore.Helpers;

/// <summary>Utilities for reading identity, permission, and status data out of a claims collection.</summary>
public static class ClaimHelper
{
    /// <summary>
    /// Evaluates boolean status claims. A claim whose name is in <paramref name="invertedClaims"/> blocks
    /// access when <c>true</c>; all other status claims block access when <c>false</c>. Missing or
    /// non-boolean claims are ignored.
    /// </summary>
    public static bool HasAccess(IEnumerable<string> statusClaimNames, IReadOnlyCollection<Claim> claims, ISet<string> invertedClaims)
    {
        foreach (var name in statusClaimNames)
        {
            var value = claims.FirstOrDefault(x => x.Type == name)?.Value;
            if (string.IsNullOrWhiteSpace(value) || !bool.TryParse(value, out var flag))
                continue;

            if (invertedClaims.Contains(name))
                flag = !flag;

            if (!flag)
                return false;
        }

        return true;
    }

    // ClaimTypes.NameIdentifier is "sub" renamed by the JWT/OIDC handler's legacy inbound claim-type mapping —
    // same value, different claim type — so it sits immediately after "sub" in the fallback chain.
    private static readonly string[] UserIdFallbacks = ["externalId", "sub", ClaimTypes.NameIdentifier, "id"];
    private static readonly string[] CompanyIdFallbacks = ["tenantId", "CompanyId"];

    private const string MetadataClaim = "metadata";
    private const string CustomClaimsClaim = "customClaims";

    /// <summary>
    /// Claim types carrying Frontegg's JSON payloads, in resolution order. The same properties arrive under
    /// <c>metadata</c> for some tenants and under <c>customClaims</c> for others, so both are searched.
    /// </summary>
    private static readonly string[] JsonPayloadClaims = [MetadataClaim, CustomClaimsClaim];

    /// <summary>
    /// Resolves the user id. A non-standard <paramref name="primaryClaimType"/> is checked first; the standard
    /// fallback chain (<c>externalId</c> → <c>sub</c> → <see cref="ClaimTypes.NameIdentifier"/> → <c>id</c>)
    /// follows. <c>externalId</c> precedes <c>sub</c> so an API-key principal (whose <c>sub</c> is the token id)
    /// resolves to the enriched user id. <see cref="ClaimTypes.NameIdentifier"/> sits right after <c>sub</c>
    /// because it is the same value renamed by the JWT/OIDC handler's legacy inbound claim-type mapping.
    /// </summary>
    public static string? GetUserId(IEnumerable<Claim> claims, string? primaryClaimType = null)
    {
        var list = claims as IList<Claim> ?? claims.ToList();
        return ResolveId(list, primaryClaimType, UserIdFallbacks)
            ?? ResolveIdFromJsonClaims(list, primaryClaimType, UserIdFallbacks);
    }

    /// <summary>
    /// Resolves the tenant/company id, checking a non-standard <paramref name="primaryClaimType"/> first, then
    /// <c>tenantId</c> → <c>CompanyId</c>, and finally the same names inside Frontegg's JSON payload claims.
    /// </summary>
    public static string? GetCompanyId(IEnumerable<Claim> claims, string? primaryClaimType = null)
    {
        var list = claims as IList<Claim> ?? claims.ToList();
        return ResolveId(list, primaryClaimType, CompanyIdFallbacks)
            ?? ResolveIdFromJsonClaims(list, primaryClaimType, CompanyIdFallbacks);
    }

    private static string? ResolveId(IEnumerable<Claim> claims, string? primaryClaimType, string[] fallbacks)
    {
        var list = claims as IList<Claim> ?? claims.ToList();
        string? Find(string t) => list.FirstOrDefault(x => x.Type.Equals(t, StringComparison.OrdinalIgnoreCase))?.Value;

        if (!string.IsNullOrEmpty(primaryClaimType)
            && !fallbacks.Contains(primaryClaimType, StringComparer.OrdinalIgnoreCase)
            && Find(primaryClaimType) is { Length: > 0 } primary)
            return primary;

        foreach (var fallback in fallbacks)
            if (Find(fallback) is { Length: > 0 } value)
                return value;

        return null;
    }

    /// <summary>
    /// Second-chance resolution for an id that is absent from the claim set but present inside one of Frontegg's
    /// JSON payload claims — the shape emitted when a tenant carries its ids in <c>metadata</c>/<c>customClaims</c>
    /// rather than as first-class claims. Tries the same names, in the same order, as <see cref="ResolveId"/>.
    /// Runs only after every claim-type lookup has come back empty, so it can never shadow a real claim.
    /// </summary>
    private static string? ResolveIdFromJsonClaims(IList<Claim> claims, string? primaryPropertyName, string[] fallbacks)
    {
        if (!string.IsNullOrEmpty(primaryPropertyName)
            && !fallbacks.Contains(primaryPropertyName, StringComparer.OrdinalIgnoreCase)
            && GetMetadataValue(claims, primaryPropertyName) is { Length: > 0 } primary)
            return primary;

        foreach (var fallback in fallbacks)
            if (GetMetadataValue(claims, fallback) is { Length: > 0 } value)
                return value;

        return null;
    }

    /// <summary>Parses comma-separated numeric permission IDs from the given claim type.</summary>
    public static int[] GetPermissionIds(IEnumerable<Claim> claims, string claimType)
    {
        var claimValue = claims.FirstOrDefault(x => x.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))?.Value;
        if (string.IsNullOrEmpty(claimValue))
            return [];

        return claimValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => int.TryParse(x, out var val) ? val : 0)
            .Where(x => x != 0)
            .ToArray();
    }

    /// <summary>Parses comma-separated string permission keys from the given claim type(s).</summary>
    public static string[] GetPermissionKeys(IEnumerable<Claim> claims, string claimType)
    {
        return claims
            .Where(x => x.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))
            .SelectMany(x => x.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Parses the distinct role keys carried by the given claim type. Unlike
    /// <see cref="GetPermissionKeys"/> a role claim holds exactly one key, so values are not split on commas.
    /// </summary>
    public static string[] GetRoleKeys(IEnumerable<Claim> claims, string claimType)
    {
        return claims
            .Where(x => x.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>Reads the kind of token presented (e.g. <c>tenantApiToken</c>) from the given claim type.</summary>
    public static string? GetTokenType(IEnumerable<Claim> claims, string claimType)
        => claims.FirstOrDefault(x => x.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))?.Value;

    /// <summary>Reads a value from the JSON <c>customClaims</c> claim (top-level or nested under <c>custom</c>).</summary>
    public static string? GetCustomClaimValue(IEnumerable<Claim> claims, string propertyName)
        => ReadJsonClaimProperty(claims, CustomClaimsClaim, propertyName);

    /// <summary>
    /// Reads a value (e.g. <c>accountName</c>, <c>companyId</c>, <c>departmentId</c>, <c>legacyUserId</c>) from
    /// Frontegg's JSON payload claims, checking <c>metadata</c> before <c>customClaims</c> and, within each,
    /// the top level before a nested <c>custom</c> object. Returns <c>null</c> when no claim carries the
    /// property, or when none of them is valid JSON.
    /// </summary>
    public static string? GetMetadataValue(IEnumerable<Claim> claims, string propertyName)
    {
        var list = claims as IList<Claim> ?? claims.ToList();

        foreach (var claimType in JsonPayloadClaims)
            if (ReadJsonClaimProperty(list, claimType, propertyName) is { } value && !string.IsNullOrWhiteSpace(value))
                return value;

        return null;
    }

    /// <summary>
    /// Reads the raw JSON of the <c>vendorMetadata</c> object from Frontegg's JSON payload claims, checking
    /// <c>metadata</c> before <c>customClaims</c> and, within each, the top level before a nested <c>custom</c>
    /// object. Returns <c>null</c> when no claim carries a <c>vendorMetadata</c> object.
    /// </summary>
    public static string? GetVendorMetadata(IEnumerable<Claim> claims)
    {
        var list = claims as IList<Claim> ?? claims.ToList();

        foreach (var claimType in JsonPayloadClaims)
        {
            var rawClaim = FindClaimValue(list, claimType);
            if (string.IsNullOrWhiteSpace(rawClaim))
                continue;

            try
            {
                using var doc = JsonDocument.Parse(rawClaim);
                if (TryGetVendorMetadataElement(doc.RootElement, out var vendor))
                    return vendor.GetRawText();
            }
            catch (JsonException)
            {
            }
        }

        return null;
    }

    private static string? FindClaimValue(IEnumerable<Claim> claims, string claimType)
        => claims.FirstOrDefault(x => x.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase))?.Value;

    /// <summary>
    /// Reads <paramref name="propertyName"/> out of the JSON carried by <paramref name="claimType"/>, checking the
    /// top level before a nested <c>custom</c> object. Malformed JSON yields <c>null</c> rather than throwing —
    /// this runs inside the authentication pipeline, where a parse failure must not fail the request.
    /// </summary>
    private static string? ReadJsonClaimProperty(IEnumerable<Claim> claims, string claimType, string propertyName)
    {
        var rawClaim = FindClaimValue(claims, claimType);
        if (string.IsNullOrWhiteSpace(rawClaim))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(rawClaim);
            var root = doc.RootElement;

            if (TryReadJsonProperty(root, propertyName, out var value))
                return value;

            if (TryFindProperty(root, "custom", out var nested) && TryReadJsonProperty(nested, propertyName, out value))
                return value;
        }
        catch (JsonException)
        {
        }

        return null;
    }

    /// <summary>Resolves the user id + tenant id pair from a claims identity.</summary>
    public static UserData GetUserDataFromClaims(ClaimsIdentity identity)
        => new(GetUserId(identity.Claims), GetCompanyId(identity.Claims));

    /// <summary>
    /// Adds <paramref name="claims"/> to <paramref name="identity"/>, skipping any type+value pair it already
    /// carries. Type comparison is case-insensitive; values are compared exactly, so a multi-valued claim type
    /// (roles, permissions) keeps every distinct value.
    /// </summary>
    public static void AddUniqueClaims(ClaimsIdentity identity, IEnumerable<Claim> claims)
    {
        foreach (var claim in claims)
        {
            var exists = identity.Claims.Any(existing =>
                existing.Type.Equals(claim.Type, StringComparison.OrdinalIgnoreCase) &&
                existing.Value.Equals(claim.Value, StringComparison.Ordinal));

            if (!exists)
                identity.AddClaim(claim);
        }
    }

    private static bool TryGetVendorMetadataElement(JsonElement root, out JsonElement vendor)
    {
        if (TryFindProperty(root, "vendorMetadata", out vendor) && vendor.ValueKind == JsonValueKind.Object)
            return true;

        if (TryFindProperty(root, "custom", out var nested)
            && TryFindProperty(nested, "vendorMetadata", out vendor) && vendor.ValueKind == JsonValueKind.Object)
            return true;

        vendor = default;
        return false;
    }

    /// <summary>
    /// Finds a property by name, exact match first and then case-insensitively. Frontegg's payload keys are
    /// camelCase while the names they are matched against (configured claim types, the <c>CompanyId</c> fallback)
    /// are not, and <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/> is case-sensitive. Also
    /// guards the <c>ValueKind</c>: calling <c>TryGetProperty</c> on a non-object throws
    /// <see cref="InvalidOperationException"/>, which the callers' <c>catch (JsonException)</c> would not hold.
    /// </summary>
    private static bool TryFindProperty(JsonElement element, string propertyName, out JsonElement property)
    {
        property = default;
        if (element.ValueKind != JsonValueKind.Object)
            return false;

        if (element.TryGetProperty(propertyName, out property))
            return true;

        foreach (var candidate in element.EnumerateObject())
        {
            if (string.Equals(candidate.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                property = candidate.Value;
                return true;
            }
        }

        property = default;
        return false;
    }

    private static bool TryReadJsonProperty(JsonElement element, string propertyName, out string? value)
    {
        value = null;
        if (!TryFindProperty(element, propertyName, out var property))
            return false;

        value = property.ValueKind switch
        {
            // A JSON null carries no value. Without this arm it falls through to GetRawText() and yields the
            // literal string "null", which downstream callers cannot distinguish from a real value.
            JsonValueKind.Null or JsonValueKind.Undefined => null,
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.GetRawText(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            // GetString() throws InvalidOperationException on a non-string element, which the callers'
            // catch (JsonException) would not hold — read the raw text for those instead.
            JsonValueKind.Array => string.Join(',', property.EnumerateArray()
                .Where(x => x.ValueKind != JsonValueKind.Null)
                .Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : x.GetRawText())
                .Where(x => !string.IsNullOrEmpty(x))),
            _ => property.GetRawText()
        };

        // A null-valued property is reported as absent so the caller keeps searching (nested `custom` object,
        // then the next payload claim) instead of stopping on a value it cannot use.
        return value is not null;
    }
}
