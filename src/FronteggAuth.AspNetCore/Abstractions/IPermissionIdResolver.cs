namespace FronteggAuth.AspNetCore.Abstractions;

/// <summary>
/// Maps a native Frontegg permission key to a numeric permission ID. Used by the default
/// claims provider to emit numeric permission claims alongside the native string keys.
/// </summary>
public interface IPermissionIdResolver
{
    /// <summary>Returns the numeric ID for <paramref name="permissionKey"/>, or <c>null</c> when unmapped.</summary>
    int? Resolve(string permissionKey);
}
