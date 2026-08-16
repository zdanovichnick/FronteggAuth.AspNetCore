using System.Text.Json.Serialization;

namespace FronteggAuth.AspNetCore.Models;

/// <summary>OAuth token response shape returned by the Frontegg token endpoint.</summary>
internal sealed class FronteggTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }
}
