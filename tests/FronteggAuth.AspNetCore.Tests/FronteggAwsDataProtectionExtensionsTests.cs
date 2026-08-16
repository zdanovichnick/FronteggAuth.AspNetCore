using AwesomeAssertions;
using FronteggAuth.AspNetCore.Configuration;
using FronteggAuth.AspNetCore.DataProtection.Aws;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace FronteggAuth.AspNetCore.Tests;

public sealed class FronteggAwsDataProtectionExtensionsTests
{
    [Fact]
    public void PersistDataProtectionKeysToSsm_NullSettings_Throws()
    {
        FronteggSettings settings = null!;

        var act = () => settings.PersistDataProtectionKeysToSsm("/app/{environment}/dataprotection");

        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PersistDataProtectionKeysToSsm_NullOrWhitespacePath_Throws(string? parameterPath)
    {
        var settings = new FronteggSettings();

        var act = () => settings.PersistDataProtectionKeysToSsm(parameterPath!);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void PersistDataProtectionKeysToSsm_SetsConfigureDataProtectionCallback()
    {
        var settings = new FronteggSettings();

        settings.PersistDataProtectionKeysToSsm("/app/{environment}/dataprotection");

        settings.ConfigureDataProtection.Should().NotBeNull();
    }

    [Fact]
    public void PersistDataProtectionKeysToSsm_ReturnsSameSettingsInstance_ForFluentChaining()
    {
        var settings = new FronteggSettings();

        var result = settings.PersistDataProtectionKeysToSsm("/app/{environment}/dataprotection");

        result.Should().BeSameAs(settings);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Development")]
    [InlineData("Staging")]
    public void PersistDataProtectionKeysToSsm_ConfiguresDataProtectionBuilder_RegardlessOfEnvironment(string? environmentVariable)
    {
        var originalEnvironment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        try
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", environmentVariable);
            var settings = new FronteggSettings();
            settings.PersistDataProtectionKeysToSsm("/app/{environment}/dataprotection");

            var services = new ServiceCollection();
            var builder = services.AddDataProtection();

            var act = () => settings.ConfigureDataProtection!(builder);

            act.Should().NotThrow();
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", originalEnvironment);
        }
    }

    [Fact]
    public void PersistDataProtectionKeysToSsm_PathWithoutPlaceholder_StillConfiguresSuccessfully()
    {
        var settings = new FronteggSettings();
        settings.PersistDataProtectionKeysToSsm("/app/production/dataprotection");

        var builder = new ServiceCollection().AddDataProtection();

        var act = () => settings.ConfigureDataProtection!(builder);

        act.Should().NotThrow();
    }
}
