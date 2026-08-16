namespace FronteggAuth.Samples.Mvc;

/// <summary>
/// The permissions this sample gates on. The package ships no permission constants of its own — Frontegg
/// permission keys are tenant-defined, so any list baked into the library would be wrong for everyone.
/// Declaring a class like this one in your application is the intended pattern.
/// </summary>
public static class SamplePermissions
{
    /// <summary>Read access to reports. Applied at controller level, so it covers every action.</summary>
    public const string ReportsRead = "sample.reports.read";

    /// <summary>Write access, stacked on top of <see cref="ReportsRead"/> to get AND semantics.</summary>
    public const string ReportsWrite = "sample.reports.write";

    /// <summary>Export access, addressed by its numeric id below rather than by key.</summary>
    public const string ReportsExport = "sample.reports.export";

    /// <summary>
    /// Numeric id for <see cref="ReportsExport"/>. Only resolves because <c>appsettings.json</c> maps it under
    /// <c>FronteggSettings:PermissionIdMappings</c>; unmapped, the numeric claim is never emitted and the gate
    /// denies for reasons that look like a missing permission.
    /// </summary>
    public const int ReportsExportId = 101;

    /// <summary>
    /// A permission whose presence <em>denies</em> access, used to demonstrate the reverse-permission form.
    /// Modelling a restriction as a permission is unusual; it exists for tenants that already do it that way.
    /// </summary>
    public const string SandboxedAccount = "sample.account.sandboxed";
}
