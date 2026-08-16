using FronteggAuth.AspNetCore.Configuration;
// PersistKeysToAWSSystemsManager is declared in Microsoft.Extensions.DependencyInjection, not in the
// Amazon.* namespace the package is named after.
using Microsoft.Extensions.DependencyInjection;

namespace FronteggAuth.AspNetCore.DataProtection.Aws;

/// <summary>
/// Persists the Data Protection key ring — which encrypts the authentication cookie — to AWS Systems Manager
/// Parameter Store, so every instance behind a load balancer can decrypt each other's cookies.
/// </summary>
public static class FronteggAwsDataProtectionExtensions
{
    /// <summary>
    /// Environment placeholder replaced in the parameter path, so one configured value serves every environment.
    /// </summary>
    public const string EnvironmentPlaceholder = "{environment}";

    /// <summary>
    /// Persists Data Protection keys to Parameter Store under <paramref name="parameterPath"/>. Any
    /// <see cref="EnvironmentPlaceholder"/> in the path is replaced with the lower-cased value of
    /// <c>ASPNETCORE_ENVIRONMENT</c> (<c>production</c> when unset).
    /// </summary>
    /// <param name="settings">The settings passed to <c>AddFronteggAuth</c>'s configure callback.</param>
    /// <param name="parameterPath">Parameter Store path, e.g. <c>/myapp/{environment}/dataprotection</c>.</param>
    /// <exception cref="ArgumentException"><paramref name="parameterPath"/> is null, empty, or whitespace.</exception>
    public static FronteggSettings PersistDataProtectionKeysToSsm(this FronteggSettings settings, string parameterPath)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentException.ThrowIfNullOrWhiteSpace(parameterPath);

        // The environment is read from the variable rather than IHostEnvironment because the callback runs at
        // service-registration time, before the host — and therefore IHostEnvironment — exists.
        var environment = (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production").ToLowerInvariant();
        var resolvedPath = parameterPath.Replace(EnvironmentPlaceholder, environment, StringComparison.OrdinalIgnoreCase);

        settings.ConfigureDataProtection = builder => builder.PersistKeysToAWSSystemsManager(resolvedPath);

        return settings;
    }
}
