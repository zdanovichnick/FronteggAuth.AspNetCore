using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Services;
using AwesomeAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class DefaultPermissionIdResolverTests
{
    [Fact]
    public void Resolve_MappedKey_ReturnsId()
    {
        // PermissionIdMappings is id->key; the resolver inverts it to key->id internally.
        var resolver = Create(new() { [123] = "fe.read" });

        resolver.Resolve("fe.read").Should().Be(123);
    }

    [Fact]
    public void Resolve_IsCaseInsensitive()
    {
        var resolver = Create(new() { [123] = "fe.read" });

        resolver.Resolve("FE.READ").Should().Be(123);
    }

    [Fact]
    public void Resolve_UnmappedKey_ReturnsNull()
    {
        var resolver = Create(new() { [123] = "fe.read" });

        resolver.Resolve("fe.delete").Should().BeNull();
    }

    [Fact]
    public void Resolve_NoMapConfigured_ReturnsNull()
    {
        var resolver = Create(null);

        resolver.Resolve("fe.read").Should().BeNull();
    }

    private static DefaultPermissionIdResolver Create(Dictionary<int, string>? map)
        => new(Options.Create(new FronteggSettings { PermissionIdMappings = map }));
}
