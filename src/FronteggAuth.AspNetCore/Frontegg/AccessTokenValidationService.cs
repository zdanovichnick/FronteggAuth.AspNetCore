using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Models;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Frontegg;

/// <summary>
/// Validates a Frontegg API-key / access token against the vendor-only introspection endpoints
/// (tenant access tokens first, then user access tokens), caching the result.
/// </summary>
internal sealed class AccessTokenValidationService(
    IHttpClientFactory httpClientFactory,
    IFronteggTokenService fronteggTokenService,
    IMemoryCache cache,
    IOptions<FronteggSettings> options,
    ILogger<AccessTokenValidationService> logger) : IAccessTokenValidationService
{
    private readonly FronteggSettings _options = options.Value;

    public async Task<AccessTokenValidationResult?> ValidateAccessTokenAsync(
        string accessTokenId, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"AccessToken:{accessTokenId}";

        if (cache.TryGetValue(cacheKey, out AccessTokenValidationResult? cached) && cached is not null)
            return cached;

        var vendorToken = await fronteggTokenService.GetVendorTokenAsync(cancellationToken);
        var baseUrl = _options.ApiBaseUrl.TrimEnd('/');

        var result = await TryValidateAsync(
            $"{baseUrl}/identity/resources/vendor-only/tenants/access-tokens/v1/{accessTokenId}",
            vendorToken, isTenantToken: true, cancellationToken);

        result ??= await TryValidateAsync(
            $"{baseUrl}/identity/resources/vendor-only/users/access-tokens/v1/{accessTokenId}",
            vendorToken, isTenantToken: false, cancellationToken);

        if (result is null)
        {
            logger.LogWarning("Access token {TokenId} not found at tenant or user vendor-only endpoints", accessTokenId);
            return null;
        }

        cache.Set(cacheKey, result, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.AccessTokenCacheDurationSeconds),
            Size = 1
        });
        return result;
    }

    private async Task<AccessTokenValidationResult?> TryValidateAsync(
        string url, string vendorToken, bool isTenantToken, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient(FronteggHttpClients.Api);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", vendorToken);

            using var response = await client.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return null;

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var tenantId = root.TryGetProperty("tenantId", out var tid) ? tid.GetString() : null;
            var userId = isTenantToken
                ? (root.TryGetProperty("createdByUserId", out var cbu) ? cbu.GetString() : null)
                : (root.TryGetProperty("userId", out var uid) ? uid.GetString() : null);
            var createdByUserId = root.TryGetProperty("createdByUserId", out var cbuid) ? cbuid.GetString() : null;
            var description = root.TryGetProperty("description", out var desc) ? desc.GetString() : null;

            string[]? roles = null;
            if (root.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
            {
                roles = rolesElement.EnumerateArray()
                    .Select(r =>
                        r.TryGetProperty("key", out var key) ? key.GetString()
                        : r.TryGetProperty("name", out var name) ? name.GetString()
                        : r.ValueKind == JsonValueKind.String ? r.GetString()
                        : null)
                    .Where(r => !string.IsNullOrEmpty(r))
                    .ToArray()!;
            }

            return new AccessTokenValidationResult
            {
                IsValid = true,
                TenantId = tenantId,
                UserId = userId,
                CreatedByUserId = createdByUserId,
                Roles = roles,
                Description = description
            };
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to validate access token at {Url}", url);
            return null;
        }
    }
}
