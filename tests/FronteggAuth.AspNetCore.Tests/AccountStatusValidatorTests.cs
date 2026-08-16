using System.Security.Claims;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.Services;
using AwesomeAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class AccountStatusValidatorTests
{
    [Fact]
    public void NullValidator_AllowsAll()
    {
        var validator = new NullAccountStatusValidator();

        validator.HasAccess([new Claim("isActive", "false")]).Should().BeTrue();
    }

    [Fact]
    public void ClaimBasedValidator_BlocksWhenStatusClaimFalse()
    {
        var validator = CreateClaimBased("isActive");

        validator.HasAccess([new Claim("isActive", "false")]).Should().BeFalse();
    }

    [Fact]
    public void ClaimBasedValidator_AllowsWhenStatusClaimTrue()
    {
        var validator = CreateClaimBased("isActive");

        validator.HasAccess([new Claim("isActive", "true")]).Should().BeTrue();
    }

    private static ClaimBasedAccountStatusValidator CreateClaimBased(params string[] statusClaims)
    {
        var options = new FronteggSettings();
        options.ClaimTypeNames.AccountStatusClaims = statusClaims;
        return new ClaimBasedAccountStatusValidator(Options.Create(options));
    }
}
