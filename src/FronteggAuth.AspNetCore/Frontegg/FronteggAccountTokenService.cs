using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Models;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Frontegg;

/// <summary>
/// Obtains and caches a Frontegg tenant (account-scoped) token via the client-credentials grant
/// at <c>POST {ApiTokenAuthority}/oauth/token</c>, transparently using the refresh-token grant when available.
/// </summary>
internal sealed class FronteggAccountTokenService(
    IHttpClientFactory httpClientFactory,
    IOptions<FronteggSettings> options,
    TimeProvider timeProvider) : IFronteggAccountTokenService, IDisposable
{
    private readonly FronteggSettings _options = options.Value;
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private string? _cachedToken;
    private string? _refreshToken;
    private DateTimeOffset _tokenExpiry;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public async Task<string> GetTenantTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedToken is not null && timeProvider.GetUtcNow() < _tokenExpiry)
            return _cachedToken;

        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            if (_cachedToken is not null && timeProvider.GetUtcNow() < _tokenExpiry)
                return _cachedToken;

            var tokenResponse = !string.IsNullOrEmpty(_refreshToken)
                ? await RefreshAsync(_refreshToken, cancellationToken)
                : await ClientCredentialsAsync(cancellationToken);

            _cachedToken = tokenResponse.AccessToken;
            _refreshToken = tokenResponse.RefreshToken;
            _tokenExpiry = timeProvider.GetUtcNow().AddSeconds(tokenResponse.ExpiresIn - 60);

            return _cachedToken;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public void Dispose() => _semaphore.Dispose();

    private async Task<FronteggTokenResponse> ClientCredentialsAsync(CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(FronteggHttpClients.Api);

        var content = new FormUrlEncodedContent([new KeyValuePair<string, string>("grant_type", "client_credentials")]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_options.EffectiveApiTokenAuthority.TrimEnd('/')}/frontegg/oauth/token")
        {
            Headers = { Authorization = BasicAuth() },
            Content = content
        };

        using var response = await client.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(ct);
            var server = response.Headers.TryGetValues("Server", out var values) ? string.Join(',', values) : "unknown";
            throw new InvalidOperationException(
                $"Frontegg tenant-token request failed: {(int)response.StatusCode} {response.ReasonPhrase}; Server={server}; Body={error}");
        }

        return await response.Content.ReadFromJsonAsync<FronteggTokenResponse>(JsonOptions, ct)
            ?? throw new InvalidOperationException("Empty token response from Frontegg.");
    }

    private async Task<FronteggTokenResponse> RefreshAsync(string refreshToken, CancellationToken ct)
    {
        var client = httpClientFactory.CreateClient(FronteggHttpClients.Api);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_options.EffectiveApiTokenAuthority.TrimEnd('/')}/frontegg/oauth/token")
        {
            Headers = { Authorization = BasicAuth() },
            Content = new FormUrlEncodedContent([new("grant_type", "refresh_token"), new("refresh_token", refreshToken)])
        };
        using var response = await client.SendAsync(request, ct);

        if (!response.IsSuccessStatusCode)
        {
            _refreshToken = null;
            return await ClientCredentialsAsync(ct);
        }

        return await response.Content.ReadFromJsonAsync<FronteggTokenResponse>(JsonOptions, ct)
            ?? throw new InvalidOperationException("Empty refresh response from Frontegg.");
    }

    private AuthenticationHeaderValue BasicAuth()
    {
        var clientId = (_options.TenantClientId ?? throw new InvalidOperationException("FronteggSettings.TenantClientId is not configured.")).Trim();
        var secret = (_options.TenantSecret ?? throw new InvalidOperationException("FronteggSettings.TenantSecret is not configured.")).Trim();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{secret}"));
        return new AuthenticationHeaderValue("Basic", credentials);
    }
}
