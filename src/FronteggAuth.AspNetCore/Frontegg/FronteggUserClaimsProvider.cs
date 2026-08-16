using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Frontegg;

/// <summary>
/// Default <see cref="IUserClaimsProvider"/> sourcing roles and permissions from the Frontegg CIAM API.
/// It obtains a vendor token, reads the tenant's role catalog (<c>GET /identity/resources/roles/v1</c>) and
/// permission catalog (<c>GET /identity/resources/permissions/v1</c>), reads the user's role assignments
/// (<c>GET /identity/resources/users/v3/roles?ids={userId}</c>), then emits role claims, native permission-key
/// claims, and — when a permission-id map/resolver is configured — numeric permission claims. All responses are
/// parsed defensively; replace this provider via <see cref="IUserClaimsProvider"/> if your tenant's payloads differ.
/// </summary>
internal sealed class FronteggUserClaimsProvider(
    IHttpClientFactory httpClientFactory,
    IFronteggTokenService tokenService,
    IPermissionIdResolver permissionIdResolver,
    IMemoryCache cache,
    IOptions<FronteggSettings> options,
    ILogger<FronteggUserClaimsProvider> logger) : IUserClaimsProvider
{
    private readonly FronteggSettings _options = options.Value;

    /// <summary>A role's canonical key plus the permission keys it grants.</summary>
    private sealed record RoleInfo(string Key, string[] PermissionKeys);

    public async Task<List<Claim>> GetUserClaimsAsync(string userId, string companyId, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"UserClaims:{userId}:{companyId}";
        if (cache.TryGetValue(cacheKey, out List<Claim>? cached) && cached is not null)
            return cached;

        try
        {
            return await FetchAndCacheAsync(cacheKey, userId, companyId, cancellationToken);
        }
        catch (FronteggClaimsUnavailableException ex) when (_options.FailOpenOnClaimsUnavailable)
        {
            // Opt-in only, and deliberately uncached: the principal stays authenticated but role- and
            // permission-less for this request, so gated endpoints 403 while a bare [Authorize] one passes.
            logger.LogError(ex, "Serving unenriched claims for user {UserId} tenant {TenantId} (fail-open)", userId, companyId);
            return [];
        }
    }

    private async Task<List<Claim>> FetchAndCacheAsync(string cacheKey, string userId, string companyId, CancellationToken cancellationToken)
    {
        var claimNames = _options.ClaimTypeNames;
        var baseUrl = _options.ApiBaseUrl.TrimEnd('/');
        var vendorToken = await tokenService.GetVendorTokenAsync(cancellationToken);

        var permissionIdToKey = await GetPermissionCatalogAsync(baseUrl, vendorToken, cancellationToken);
        var roleCatalog = await GetRoleCatalogAsync(baseUrl, vendorToken, companyId, permissionIdToKey, cancellationToken);
        var userRoleRefs = await GetUserRoleRefsAsync(baseUrl, vendorToken, userId, companyId, cancellationToken);

        var resolvedRoles = userRoleRefs
            .Select(r => roleCatalog.TryGetValue(r, out var info) ? info : new RoleInfo(r, []))
            .ToArray();

        var roleKeys = resolvedRoles
            .Select(r => r.Key)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var permissionKeys = resolvedRoles
            .SelectMany(r => r.PermissionKeys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var claims = new List<Claim>();

        foreach (var role in roleKeys)
            claims.Add(new Claim(claimNames.Role, role));

        if (permissionKeys.Length > 0)
            claims.Add(new Claim(claimNames.Permissions, string.Join(',', permissionKeys)));

        var permissionIds = permissionKeys
            .Select(permissionIdResolver.Resolve)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .Distinct()
            .ToArray();

        if (permissionIds.Length > 0)
            claims.Add(new Claim(claimNames.PermissionIds, string.Join(',', permissionIds)));

        cache.Set(cacheKey, claims, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.ClaimsCacheDurationSeconds),
            Size = 1
        });
        return claims;
    }

    /// <summary>Returns a map of Frontegg permission id → permission key.</summary>
    private async Task<Dictionary<string, string>> GetPermissionCatalogAsync(string baseUrl, string vendorToken, CancellationToken ct)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var root = await GetJsonAsync($"{baseUrl}/identity/resources/permissions/v1", vendorToken, tenantId: null, ct);

        foreach (var permission in EnumerateArray(root))
        {
            var id = permission.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
            var key = permission.TryGetProperty("key", out var keyEl) ? keyEl.GetString() : null;
            if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(key))
                map[id] = key;
        }

        return map;
    }

    /// <summary>Returns a map keyed by role id <em>and</em> role key, each pointing to that role's <see cref="RoleInfo"/>.</summary>
    private async Task<Dictionary<string, RoleInfo>> GetRoleCatalogAsync(
        string baseUrl, string vendorToken, string tenantId, IReadOnlyDictionary<string, string> permissionIdToKey, CancellationToken ct)
    {
        var catalog = new Dictionary<string, RoleInfo>(StringComparer.OrdinalIgnoreCase);
        var root = await GetJsonAsync($"{baseUrl}/identity/resources/roles/v1", vendorToken, tenantId, ct);

        foreach (var role in EnumerateArray(root))
        {
            var id = role.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
            var key = role.TryGetProperty("key", out var keyEl) ? keyEl.GetString() : null;
            var canonicalKey = key ?? id;
            if (string.IsNullOrEmpty(canonicalKey))
                continue;

            var permissionKeys = role.TryGetProperty("permissions", out var permsEl) && permsEl.ValueKind == JsonValueKind.Array
                ? permsEl.EnumerateArray()
                    .Select(p => p.ValueKind == JsonValueKind.String ? p.GetString()
                        : p.TryGetProperty("key", out var pk) ? pk.GetString()
                        : p.TryGetProperty("id", out var pid) ? pid.GetString()
                        : null)
                    .Where(p => !string.IsNullOrEmpty(p))
                    .Select(p => permissionIdToKey.TryGetValue(p!, out var mapped) ? mapped : p!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
                : [];

            var info = new RoleInfo(canonicalKey, permissionKeys);

            // Index by both id and key so a user role reference resolves regardless of which Frontegg returns.
            if (!string.IsNullOrEmpty(key))
                catalog[key] = info;
            if (!string.IsNullOrEmpty(id))
                catalog[id] = info;
        }

        return catalog;
    }

    /// <summary>Returns the role references (ids and/or keys) assigned to the user within the tenant.</summary>
    private async Task<string[]> GetUserRoleRefsAsync(
        string baseUrl, string vendorToken, string userId, string tenantId, CancellationToken ct)
    {
        var url = $"{baseUrl}/identity/resources/users/v3/roles?ids={Uri.EscapeDataString(userId)}";
        var root = await GetJsonAsync(url, vendorToken, tenantId, ct);

        var roleRefs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in EnumerateArray(root))
        {
            // Each entry may carry a "roleIds" string array and/or a "roles" array of objects/strings.
            if (entry.TryGetProperty("roleIds", out var roleIds) && roleIds.ValueKind == JsonValueKind.Array)
                foreach (var r in roleIds.EnumerateArray())
                    AddRoleRef(roleRefs, r);

            if (entry.TryGetProperty("roles", out var roles) && roles.ValueKind == JsonValueKind.Array)
                foreach (var r in roles.EnumerateArray())
                    AddRoleRef(roleRefs, r);
        }

        return roleRefs.ToArray();
    }

    private static void AddRoleRef(HashSet<string> set, JsonElement element)
    {
        var value = element.ValueKind == JsonValueKind.String ? element.GetString()
            : element.TryGetProperty("key", out var key) ? key.GetString()
            : element.TryGetProperty("id", out var id) ? id.GetString()
            : null;

        if (!string.IsNullOrEmpty(value))
            set.Add(value);
    }

    /// <summary>
    /// Issues a vendor-authenticated GET and returns the parsed body. A failed request throws
    /// <see cref="FronteggClaimsUnavailableException"/> rather than yielding an empty result: the caller cannot
    /// tell "the user holds nothing" from "we could not ask", and the second must not be cached or served as
    /// the first. Payload <em>shape</em> is still handled leniently — that is a tenant-by-tenant variation, not
    /// a failure — so only transport, status, and parse errors reach here.
    /// </summary>
    private async Task<JsonElement> GetJsonAsync(string url, string vendorToken, string? tenantId, CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(FronteggHttpClients.Api);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", vendorToken);
            if (!string.IsNullOrEmpty(tenantId))
                request.Headers.TryAddWithoutValidation("frontegg-tenant-id", tenantId);

            using var response = await client.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
                throw new FronteggClaimsUnavailableException(
                    $"Frontegg request to {url} returned {(int)response.StatusCode} {response.ReasonPhrase}.");

            var json = await response.Content.ReadAsStringAsync(ct);
            // Clone so the JsonDocument can be disposed while the element is returned.
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller's request went away — not a Frontegg failure, don't report it as one.
            throw;
        }
        catch (Exception ex) when (ex is not FronteggClaimsUnavailableException)
        {
            throw new FronteggClaimsUnavailableException($"Frontegg request to {url} failed.", ex);
        }
    }

    /// <summary>Enumerates a JSON array, tolerating list responses wrapped in an <c>items</c> property.</summary>
    private static IEnumerable<JsonElement> EnumerateArray(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
            return element.EnumerateArray();

        if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
            return items.EnumerateArray();

        return [];
    }
}
