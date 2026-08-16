using System.Security.Claims;
using FronteggAuth.AspNetCore.Helpers;
using AwesomeAssertions;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class ClaimHelperTests
{
    [Fact]
    public void HasAccess_AllStatusClaimsTrue_ReturnsTrue()
    {
        var claims = new[] { new Claim("isActive", "true"), new Claim("isApproved", "true") };

        var result = ClaimHelper.HasAccess(["isActive", "isApproved"], claims, EmptyInverted);

        result.Should().BeTrue();
    }

    [Fact]
    public void HasAccess_NormalStatusClaimFalse_ReturnsFalse()
    {
        var claims = new[] { new Claim("isActive", "false") };

        var result = ClaimHelper.HasAccess(["isActive"], claims, EmptyInverted);

        result.Should().BeFalse();
    }

    [Fact]
    public void HasAccess_InvertedClaimTrue_ReturnsFalse()
    {
        var claims = new[] { new Claim("logout", "true") };
        var inverted = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "logout" };

        var result = ClaimHelper.HasAccess(["logout"], claims, inverted);

        result.Should().BeFalse();
    }

    [Fact]
    public void HasAccess_MissingClaim_IsIgnored()
    {
        var claims = Array.Empty<Claim>();

        var result = ClaimHelper.HasAccess(["isActive"], claims, EmptyInverted);

        result.Should().BeTrue();
    }

    [Fact]
    public void GetPermissionIds_ParsesCommaSeparatedIntegers()
    {
        var claims = new[] { new Claim("Permission", "1, 2,3, x") };

        var result = ClaimHelper.GetPermissionIds(claims, "Permission");

        result.Should().Equal(1, 2, 3);
    }

    [Fact]
    public void GetPermissionKeys_ParsesDistinctKeys()
    {
        var claims = new[] { new Claim("permissions", "fe.read, fe.write, fe.read") };

        var result = ClaimHelper.GetPermissionKeys(claims, "permissions");

        result.Should().BeEquivalentTo("fe.read", "fe.write");
    }

    [Fact]
    public void GetUserId_PrefersExternalIdOverSub()
    {
        var claims = new[] { new Claim("sub", "token-id"), new Claim("externalId", "user-1") };

        var result = ClaimHelper.GetUserId(claims, "sub");

        result.Should().Be("user-1");
    }

    [Fact]
    public void GetUserId_NonStandardPrimaryClaim_Wins()
    {
        var claims = new[] { new Claim("userId", "u-9"), new Claim("sub", "s") };

        var result = ClaimHelper.GetUserId(claims, "userId");

        result.Should().Be("u-9");
    }

    [Fact]
    public void GetCompanyId_ResolvesTenantId()
    {
        var claims = new[] { new Claim("tenantId", "tenant-7") };

        var result = ClaimHelper.GetCompanyId(claims, "tenantId");

        result.Should().Be("tenant-7");
    }

    [Fact]
    public void GetTokenType_ReadsClaimCaseInsensitively()
    {
        var claims = new[] { new Claim("Type", "tenantApiToken") };

        var result = ClaimHelper.GetTokenType(claims, "type");

        result.Should().Be("tenantApiToken");
    }

    [Fact]
    public void GetTokenType_MissingClaim_ReturnsNull()
    {
        var claims = new[] { new Claim("sub", "user-1") };

        var result = ClaimHelper.GetTokenType(claims, "type");

        result.Should().BeNull();
    }

    [Fact]
    public void GetVendorMetadata_ReturnsRawJsonOfNestedObject()
    {
        const string vendor = """{"externalId":"65837b2f-887a-eb11-819c-829225aaae23","accountName":"Contoso","accountId":"1","status":"Active"}""";
        var json = $$"""{"externalId":"65837b2f-887a-eb11-819c-829225aaae23","accountName":"Contoso","vendorMetadata":{{vendor}}}""";
        var claims = new[] { new Claim("customClaims", json) };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().Be(vendor);
    }

    [Fact]
    public void GetVendorMetadata_ReadsFromNestedCustomObject()
    {
        const string vendor = """{"accountName":"Acme","accountId":"42","status":"Active"}""";
        var json = """{"custom":{"vendorMetadata":""" + vendor + "}}";
        var claims = new[] { new Claim("customClaims", json) };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().Be(vendor);
    }

    [Fact]
    public void GetVendorMetadata_MissingVendorMetadata_ReturnsNull()
    {
        var claims = new[] { new Claim("customClaims", """{"accountName":"Contoso"}""") };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().BeNull();
    }

    [Fact]
    public void GetVendorMetadata_InvalidJson_ReturnsNull()
    {
        var claims = new[] { new Claim("customClaims", "not-json") };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().BeNull();
    }

    [Fact]
    public void GetVendorMetadata_NoCustomClaim_ReturnsNull()
    {
        var claims = Array.Empty<Claim>();

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_ReadsFromMetadataClaim()
    {
        var claims = new[] { new Claim("metadata", """{"accountName":"Perdue Chicken"}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().Be("Perdue Chicken");
    }

    [Fact]
    public void GetMetadataValue_MetadataAbsent_FallsBackToCustomClaims()
    {
        var claims = new[] { new Claim("customClaims", """{"accountName":"Contoso"}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().Be("Contoso");
    }

    [Fact]
    public void GetMetadataValue_MetadataClaimWins_OverCustomClaims()
    {
        var claims = new[]
        {
            new Claim("metadata", """{"accountName":"From Metadata"}"""),
            new Claim("customClaims", """{"accountName":"From CustomClaims"}""")
        };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().Be("From Metadata");
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"accountName":""}""")]
    [InlineData("""{"accountName":"   "}""")]
    [InlineData("""{"accountName":null}""")]
    [InlineData("not-json")]
    [InlineData("[1,2,3]")]
    public void GetMetadataValue_UnusableMetadata_FallsBackToCustomClaims(string metadata)
    {
        var claims = new[]
        {
            new Claim("metadata", metadata),
            new Claim("customClaims", """{"accountName":"Contoso"}""")
        };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().Be("Contoso");
    }

    [Fact]
    public void GetMetadataValue_NoJsonPayloadClaims_ReturnsNull()
    {
        var claims = new[] { new Claim("sub", "user-1") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_BothClaimsMalformed_ReturnsNull()
    {
        var claims = new[] { new Claim("metadata", "not-json"), new Claim("customClaims", "{oops") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_NonObjectJson_ReturnsNullWithoutThrowing()
    {
        var claims = new[] { new Claim("metadata", """["a","b"]"""), new Claim("customClaims", "\"scalar\"") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_NullValuedProperty_ReturnsNullNotTheLiteralString()
    {
        var claims = new[] { new Claim("metadata", """{"accountName":null}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_NullValuedTopLevelProperty_FallsBackToNestedCustomObject()
    {
        var claims = new[] { new Claim("metadata", """{"accountName":null,"custom":{"accountName":"Contoso"}}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "accountName");

        result.Should().Be("Contoso");
    }

    [Fact]
    public void GetUserId_NullValuedJsonFallback_DoesNotResolveToTheLiteralString()
    {
        var claims = new[] { new Claim("metadata", """{"externalId":null}""") };

        var result = ClaimHelper.GetUserId(claims);

        result.Should().BeNull();
    }

    [Fact]
    public void GetMetadataValue_ReadsFromNestedCustomObject()
    {
        var claims = new[] { new Claim("metadata", """{"custom":{"departmentId":"7"}}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "departmentId");

        result.Should().Be("7");
    }

    [Fact]
    public void GetMetadataValue_MatchesPropertyNameCaseInsensitively()
    {
        var claims = new[] { new Claim("metadata", """{"companyId":"45"}""") };

        var result = ClaimHelper.GetMetadataValue(claims, "CompanyId");

        result.Should().Be("45");
    }

    [Theory]
    [InlineData("""{"value":45}""", "45")]
    [InlineData("""{"value":true}""", "True")]
    [InlineData("""{"value":false}""", "False")]
    [InlineData("""{"value":["a","b"]}""", "a,b")]
    [InlineData("""{"value":[1,2]}""", "1,2")]
    [InlineData("""{"value":["a",null,"b"]}""", "a,b")]
    [InlineData("""{"value":{"nested":1}}""", """{"nested":1}""")]
    public void GetMetadataValue_ConvertsNonStringValues(string metadata, string expected)
    {
        var claims = new[] { new Claim("metadata", metadata) };

        var result = ClaimHelper.GetMetadataValue(claims, "value");

        result.Should().Be(expected);
    }

    [Fact]
    public void GetCustomClaimValue_DoesNotReadMetadataClaim()
    {
        var claims = new[] { new Claim("metadata", """{"accountName":"Perdue Chicken"}""") };

        var result = ClaimHelper.GetCustomClaimValue(claims, "accountName");

        result.Should().BeNull();
    }

    [Fact]
    public void GetVendorMetadata_ReadsFromMetadataClaim()
    {
        const string vendor = """{"accountName":"Perdue Chicken","accountId":"45","status":"Active"}""";
        var claims = new[] { new Claim("metadata", $$"""{"vendorMetadata":{{vendor}}}""") };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().Be(vendor);
    }

    [Fact]
    public void GetVendorMetadata_MalformedMetadata_FallsBackToCustomClaims()
    {
        const string vendor = """{"accountId":"45"}""";
        var claims = new[]
        {
            new Claim("metadata", "not-json"),
            new Claim("customClaims", $$"""{"vendorMetadata":{{vendor}}}""")
        };

        var result = ClaimHelper.GetVendorMetadata(claims);

        result.Should().Be(vendor);
    }

    [Theory]
    [InlineData("metadata")]
    [InlineData("customClaims")]
    public void GetCompanyId_ResolvesFromJsonPayloadClaim_WhenNoTenantClaimExists(string claimType)
    {
        var claims = new[] { new Claim("sub", "user-1"), new Claim(claimType, """{"companyId":"45"}""") };

        var result = ClaimHelper.GetCompanyId(claims, "tenantId");

        result.Should().Be("45");
    }

    [Fact]
    public void GetCompanyId_TenantClaim_WinsOverJsonPayload()
    {
        var claims = new[] { new Claim("tenantId", "tenant-7"), new Claim("metadata", """{"companyId":"45"}""") };

        var result = ClaimHelper.GetCompanyId(claims, "tenantId");

        result.Should().Be("tenant-7");
    }

    [Fact]
    public void GetCompanyId_NonStandardPrimaryPropertyInJsonPayload_Wins()
    {
        var claims = new[] { new Claim("metadata", """{"accountId":"99","companyId":"45"}""") };

        var result = ClaimHelper.GetCompanyId(claims, "accountId");

        result.Should().Be("99");
    }

    [Fact]
    public void GetUserId_ResolvesFromJsonPayloadClaim_WhenNoIdClaimExists()
    {
        var claims = new[] { new Claim("metadata", """{"externalId":"43e1db3a-61f7-ee11-ba3b-06b31fe9790d"}""") };

        var result = ClaimHelper.GetUserId(claims, "sub");

        result.Should().Be("43e1db3a-61f7-ee11-ba3b-06b31fe9790d");
    }

    [Fact]
    public void GetUserId_SubClaim_WinsOverJsonPayload()
    {
        var claims = new[] { new Claim("sub", "user-1"), new Claim("metadata", """{"externalId":"from-metadata"}""") };

        var result = ClaimHelper.GetUserId(claims, "sub");

        result.Should().Be("user-1");
    }

    [Fact]
    public void GetUserDataFromClaims_ResolvesBothIdsFromJsonPayload()
    {
        var identity = new ClaimsIdentity([
            new Claim("metadata", """{"externalId":"user-1","companyId":"45"}""")
        ]);

        var result = ClaimHelper.GetUserDataFromClaims(identity);

        result.UserId.Should().Be("user-1");
        result.CompanyId.Should().Be("45");
    }

    [Fact]
    public void GetRoleKeys_ReturnsEveryValueOfTheRoleClaim()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "editor"),
            new Claim("permissions", "fe.secure.read")
        };

        var result = ClaimHelper.GetRoleKeys(claims, ClaimTypes.Role);

        result.Should().Equal("admin", "editor");
    }

    [Fact]
    public void GetRoleKeys_CollapsesValuesDifferingOnlyByCase()
    {
        var claims = new[] { new Claim(ClaimTypes.Role, "Admin"), new Claim(ClaimTypes.Role, "admin") };

        var result = ClaimHelper.GetRoleKeys(claims, ClaimTypes.Role);

        result.Should().Equal("Admin");
    }

    [Fact]
    public void GetRoleKeys_MatchesClaimTypeCaseInsensitively()
    {
        var claims = new[] { new Claim("ROLE", "admin") };

        var result = ClaimHelper.GetRoleKeys(claims, "role");

        result.Should().Equal("admin");
    }

    // A role claim carries a single key, so a comma is part of the name rather than a separator —
    // unlike the permission claims, which are comma-packed.
    [Fact]
    public void GetRoleKeys_DoesNotSplitOnCommas()
    {
        var claims = new[] { new Claim(ClaimTypes.Role, "admin,editor") };

        var result = ClaimHelper.GetRoleKeys(claims, ClaimTypes.Role);

        result.Should().Equal("admin,editor");
    }

    [Fact]
    public void GetRoleKeys_WhenNoMatchingClaim_ReturnsEmpty()
    {
        var claims = new[] { new Claim("permissions", "fe.secure.read") };

        var result = ClaimHelper.GetRoleKeys(claims, ClaimTypes.Role);

        result.Should().BeEmpty();
    }

    private static readonly HashSet<string> EmptyInverted = new(StringComparer.OrdinalIgnoreCase);
}
