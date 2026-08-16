using System.Net.Http.Json;
using System.Text.Json;
using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Frontegg;

/// <summary>
/// Obtains and caches a Frontegg vendor (machine-to-machine) token via
/// <c>POST {ApiBaseUrl}/auth/vendor</c> with the configured client id and API key. The vendor token
/// authorizes calls to the Frontegg management and vendor-only endpoints.
/// </summary>
internal sealed class FronteggTokenService : IFronteggTokenService, IDisposable
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly FronteggSettings _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<FronteggTokenService> _logger;
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    private string? _cachedToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromSeconds(60);

    public FronteggTokenService(
        IHttpClientFactory httpClientFactory,
        IOptions<FronteggSettings> options,
        TimeProvider timeProvider,
        ILogger<FronteggTokenService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<string> GetVendorTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_cachedToken is not null && _timeProvider.GetUtcNow() < _expiresAt - RefreshBuffer)
            return _cachedToken;

        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            if (_cachedToken is not null && _timeProvider.GetUtcNow() < _expiresAt - RefreshBuffer)
                return _cachedToken;

            return await RefreshTokenAsync(cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task<string> RefreshTokenAsync(CancellationToken cancellationToken)
    {
        var url = $"{_options.ApiBaseUrl.TrimEnd('/')}/auth/vendor";
        var client = _httpClientFactory.CreateClient(FronteggHttpClients.Api);

        _logger.LogDebug("Refreshing Frontegg vendor token from {Url}", url);

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(new { clientId = _options.ClientId, secret = _options.ApiKey })
        };

        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var token = (root.TryGetProperty("token", out var t) ? t.GetString() : null)
            ?? (root.TryGetProperty("access_token", out var at) ? at.GetString() : null)
            ?? throw new InvalidOperationException("Frontegg vendor auth endpoint returned no token.");

        var expiresIn = root.TryGetProperty("expiresIn", out var ei) && ei.TryGetInt32(out var eiv) ? eiv
            : root.TryGetProperty("expires_in", out var ei2) && ei2.TryGetInt32(out var eiv2) ? eiv2
            : 3600;

        _cachedToken = token;
        _expiresAt = _timeProvider.GetUtcNow().AddSeconds(expiresIn);

        _logger.LogInformation("Frontegg vendor token refreshed; expires at {ExpiresAt} (in {ExpiresIn}s)", _expiresAt, expiresIn);

        return token;
    }

    public void Dispose() => _semaphore.Dispose();
}
