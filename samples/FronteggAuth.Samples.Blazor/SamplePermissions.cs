namespace FronteggAuth.Samples.Blazor;

/// <summary>
/// The permissions this sample gates on, in both representations. The package deliberately ships no permission
/// constants — Frontegg permission keys are tenant-defined, so any list baked into the library would be wrong
/// for everyone. Declaring a class like this one in your own application is the intended pattern.
/// </summary>
/// <remarks>
/// <see cref="ReportsReadId"/> only resolves when the host maps it, via
/// <c>FronteggSettings.PermissionIdMappings</c> or a custom <c>IPermissionIdResolver</c>. Without a mapping the
/// numeric claim is never emitted and every <c>permid:</c> gate denies.
/// </remarks>
public static class SamplePermissions
{
    /// <summary>Native Frontegg permission key. Replace with a key that exists in your tenant.</summary>
    public const string ReportsRead = "sample.reports.read";

    /// <summary>Numeric id mapped to <see cref="ReportsRead"/> by this sample's <c>appsettings.json</c>.</summary>
    public const int ReportsReadId = 100;

    /// <summary>
    /// Policy name for <see cref="ReportsRead"/>. The package's policy provider materializes any policy starting
    /// with <c>perm:</c> on demand, so nothing has to be registered for this name to resolve — but a component
    /// attribute needs a compile-time constant, which is why it is declared rather than composed inline.
    /// </summary>
    public const string ReportsReadPolicy = "perm:" + ReportsRead;
}
