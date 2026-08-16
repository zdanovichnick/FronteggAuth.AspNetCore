namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Thrown by an <see cref="IUserClaimsProvider"/> when the authority that owns the user's roles and permissions
/// could not be reached or answered with a failure — as distinct from answering that the user holds nothing.
/// </summary>
/// <remarks>
/// The distinction is a security boundary, not a diagnostic nicety. The claims-enrichment middleware turns this
/// into a 401, so an outage denies access; swallowing it would leave the principal authenticated but stripped of
/// every role and permission, which passes a bare <c>[Authorize]</c> endpoint. Providers should throw this rather
/// than return an empty claim list, and must not cache the empty result. Set
/// <c>FronteggSettings.FailOpenOnClaimsUnavailable</c> to opt into the weaker behaviour.
/// </remarks>
public sealed class FronteggClaimsUnavailableException : Exception
{
    /// <summary>Creates the exception with a message describing the failed request.</summary>
    public FronteggClaimsUnavailableException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception wrapping the underlying transport or parse failure.</summary>
    public FronteggClaimsUnavailableException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
