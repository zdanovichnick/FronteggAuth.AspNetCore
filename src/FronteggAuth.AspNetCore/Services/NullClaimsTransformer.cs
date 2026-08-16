using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>Default no-op <see cref="IClaimsTransformer"/>.</summary>
internal sealed class NullClaimsTransformer : IClaimsTransformer
{
    public void Transform(ClaimsIdentity identity)
    {
    }
}
