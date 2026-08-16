using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Frontegg;

/// <summary>
/// Obtains and caches a Frontegg user-scoped JWT via email lookup, PAT creation/reuse, and token exchange.
/// Maintains per-email PAT credentials in memory and re-exchanges them on JWT expiry rather than creating
/// a new PAT per refresh.
/// </summary>
internal sealed class FronteggUserTokenService : IFronteggUserTokenService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly FronteggSettings _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<FronteggUserTokenService> _logger;
    private readonly IFronteggTokenService _tokenService;

    private readonly ConcurrentDictionary<string, CachedUserToken> _tokenCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _semaphores = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(60);

    public FronteggUserTokenService(
        IHttpClientFactory httpClientFactory,
        IOptions<FronteggSettings> options,
        TimeProvider timeProvider,
        ILogger<FronteggUserTokenService> logger,
        IFronteggTokenService tokenService)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _timeProvider = timeProvider;
        _logger = logger;
        _tokenService = tokenService;
    }

    public async Task<string> GetUserTokenAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be null or whitespace.", nameof(email));

        // Fast-path: check cache without lock
        if (_tokenCache.TryGetValue(email, out var cached) &&
            _timeProvider.GetUtcNow() < cached.ExpiresAt - RefreshBuffer)
        {
            return cached.Token ?? throw new InvalidOperationException("Cached token is null.");
        }

        // Per-email semaphore for serialized PAT creation and token exchange
        var semaphore = _semaphores.GetOrAdd(email, _ => new SemaphoreSlim(1, 1));

        await semaphore.WaitAsync(cancellationToken);
        try
        {
            // Double-check after acquiring semaphore
            if (_tokenCache.TryGetValue(email, out cached) &&
                _timeProvider.GetUtcNow() < cached.ExpiresAt - RefreshBuffer)
            {
                return cached.Token ?? throw new InvalidOperationException("Cached token is null.");
            }

            // Retrieve vendor token for PAT creation (if needed)
            var vendorToken = await _tokenService.GetVendorTokenAsync(cancellationToken);

            // Acquire or refresh PAT credentials
            var entry = _tokenCache.AddOrUpdate(
                email,
                new CachedUserToken(),
                (_, existing) => existing);

            var clientId = entry.PatClientId;
            var secret = entry.PatSecret;

            if (clientId == null || secret == null)
            {
                // Create new PAT
                var pat = await ResolveUserAndCreatePatAsync(email, vendorToken, cancellationToken);
                clientId = pat.ClientId ?? throw new InvalidOperationException("PAT ClientId is null.");
                secret = pat.Secret ?? throw new InvalidOperationException("PAT Secret is null.");

                // Replace entry with updated PAT credentials
                entry = new CachedUserToken
                {
                    PatClientId = clientId,
                    PatSecret = secret
                };
                _tokenCache[email] = entry;
            }

            // Exchange PAT for user JWT
            var jwt = await ExchangePatForJwtAsync(clientId, secret, cancellationToken);
            var token = jwt.AccessToken ?? throw new InvalidOperationException("JWT AccessToken is null.");

            // Replace entry with new token
            entry = new CachedUserToken
            {
                PatClientId = clientId,
                PatSecret = secret,
                Token = token,
                ExpiresAt = _timeProvider.GetUtcNow().AddSeconds(jwt.ExpiresIn - 60)
            };
            _tokenCache[email] = entry;

            return token;
        }
        finally
        {
            semaphore.Release();
        }
    }

    private async Task<UserPatCredentials> ResolveUserAndCreatePatAsync(
        string email,
        string vendorToken,
        CancellationToken cancellationToken)
    {
        // Step 1: Resolve user by email
        var userUrl = $"{_options.ApiBaseUrl.TrimEnd('/')}/identity/resources/users/v1/email?email={Uri.EscapeDataString(email)}";
        var client = _httpClientFactory.CreateClient(FronteggHttpClients.Api);

        _logger.LogDebug("Resolving Frontegg user by email from {Url}", userUrl);

        using var userRequest = new HttpRequestMessage(HttpMethod.Get, userUrl)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", vendorToken) }
        };

        using var userResponse = await client.SendAsync(userRequest, cancellationToken);

        if (userResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            throw new InvalidOperationException($"Frontegg user not found: {email}");
        }

        userResponse.EnsureSuccessStatusCode();

        var userJson = await userResponse.Content.ReadAsStringAsync(cancellationToken);
        using var userDoc = JsonDocument.Parse(userJson);
        var userRoot = userDoc.RootElement;

        if (!userRoot.TryGetProperty("id", out var userId))
            throw new InvalidOperationException("Frontegg user response missing 'id' field.");
        if (!userRoot.TryGetProperty("tenantId", out var tenantId))
            throw new InvalidOperationException("Frontegg user response missing 'tenantId' field.");

        var userIdStr = userId.GetString() ?? throw new InvalidOperationException("User id is null.");
        var tenantIdStr = tenantId.GetString() ?? throw new InvalidOperationException("Tenant id is null.");

        // Step 2: Create PAT (personal access token)
        var patUrl = $"{_options.ApiBaseUrl.TrimEnd('/')}/identity/resources/users/access-tokens/v1";

        _logger.LogDebug("Creating Frontegg PAT from {Url}", patUrl);

        using var patRequest = new HttpRequestMessage(HttpMethod.Post, patUrl)
        {
            Content = JsonContent.Create(new { description = _options.UserTokenDescription })
        };
        patRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", vendorToken);
        patRequest.Headers.Add("frontegg-user-id", userIdStr);
        patRequest.Headers.Add("frontegg-tenant-id", tenantIdStr);

        using var patResponse = await client.SendAsync(patRequest, cancellationToken);

        if (!patResponse.IsSuccessStatusCode)
        {
            var errorBody = await patResponse.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException(
                $"Frontegg PAT creation failed: {(int)patResponse.StatusCode} {patResponse.ReasonPhrase}; Body={errorBody}");
        }

        var patJson = await patResponse.Content.ReadAsStringAsync(cancellationToken);
        using var patDoc = JsonDocument.Parse(patJson);
        var patRoot = patDoc.RootElement;

        var clientId = (patRoot.TryGetProperty("clientId", out var cid) ? cid.GetString() : null)
            ?? (patRoot.TryGetProperty("id", out var id) ? id.GetString() : null)
            ?? throw new InvalidOperationException("Frontegg PAT response missing 'clientId' or 'id' field.");

        var secret = (patRoot.TryGetProperty("secret", out var sec) ? sec.GetString() : null)
            ?? throw new InvalidOperationException("Frontegg PAT response missing 'secret' field.");

        _logger.LogInformation("Frontegg PAT created for user {UserId}", userIdStr);

        return new UserPatCredentials { ClientId = clientId, Secret = secret };
    }

    private async Task<UserJwtResponse> ExchangePatForJwtAsync(
        string clientId,
        string secret,
        CancellationToken cancellationToken)
    {
        var exchangeUrl = $"{_options.ApiBaseUrl.TrimEnd('/')}/identity/resources/auth/v2/api-token";
        var client = _httpClientFactory.CreateClient(FronteggHttpClients.Api);

        _logger.LogDebug("Exchanging PAT for user JWT at {Url}", exchangeUrl);

        using var request = new HttpRequestMessage(HttpMethod.Post, exchangeUrl)
        {
            Content = JsonContent.Create(new { clientId, secret })
        };

        using var response = await client.SendAsync(request, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException(
                $"Frontegg user token exchange failed: {(int)response.StatusCode} {response.ReasonPhrase}; Body={errorBody}");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var token = (root.TryGetProperty("accessToken", out var t) ? t.GetString() : null)
            ?? (root.TryGetProperty("access_token", out var at) ? at.GetString() : null)
            ?? (root.TryGetProperty("token", out var tok) ? tok.GetString() : null)
            ?? throw new InvalidOperationException("Frontegg user token response contains no token.");

        var expiresIn = root.TryGetProperty("expiresIn", out var ei) && ei.TryGetInt32(out var eiv) ? eiv
            : root.TryGetProperty("expires_in", out var ei2) && ei2.TryGetInt32(out var eiv2) ? eiv2
            : 3600;

        _logger.LogInformation("Frontegg user token obtained; expires in {ExpiresIn}s", expiresIn);

        return new UserJwtResponse { AccessToken = token, ExpiresIn = expiresIn };
    }

    private sealed class CachedUserToken
    {
        public string? Token { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public string? PatClientId { get; set; }
        public string? PatSecret { get; set; }
    }

    private sealed class UserPatCredentials
    {
        public string? ClientId { get; set; }
        public string? Secret { get; set; }
    }

    private sealed class UserJwtResponse
    {
        public string? AccessToken { get; set; }
        public int ExpiresIn { get; set; }
    }
}
