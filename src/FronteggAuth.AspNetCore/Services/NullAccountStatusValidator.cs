using System.Security.Claims;
using FronteggAuth.AspNetCore.Abstractions;

namespace FronteggAuth.AspNetCore.Services;

/// <summary>Default <see cref="IAccountStatusValidator"/> that allows all authenticated principals.</summary>
internal sealed class NullAccountStatusValidator : IAccountStatusValidator
{
    public bool HasAccess(IReadOnlyCollection<Claim> claims) => true;
}
