using FronteggAuth.AspNetCore.Abstractions;
using FronteggAuth.AspNetCore.Configuration;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>
/// Default <see cref="IPermissionIdResolver"/> backed by <see cref="FronteggSettings.PermissionIdMappings"/>
/// (id → key). At construction time the map is inverted to a case-insensitive key → id lookup so that
/// <see cref="Resolve"/> can accept a permission key and return the corresponding numeric ID.
/// </summary>
internal sealed class DefaultPermissionIdResolver : IPermissionIdResolver
{
    private readonly IReadOnlyDictionary<string, int> _keyToId;

    public DefaultPermissionIdResolver(IOptions<FronteggSettings> options)
    {
        // PermissionIdMappings stores id->key; invert to key->id for O(1) resolve by key.
        _keyToId = options.Value.PermissionIdMappings is { Count: > 0 } map
            ? new Dictionary<string, int>(
                map.Select(kvp => new KeyValuePair<string, int>(kvp.Value, kvp.Key)),
                StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    }

    public int? Resolve(string permissionKey)
        => _keyToId.TryGetValue(permissionKey, out var id) ? id : null;
}
