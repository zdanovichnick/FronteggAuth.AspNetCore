namespace FronteggAuth.Samples.Api;

/// <summary>
/// The permissions this sample gates on, in both representations. The package deliberately ships no permission
/// constants — Frontegg permission keys are tenant-defined, so any list baked into the library would be wrong
/// for everyone. Declaring a class like this one in your own application is the intended pattern.
/// </summary>
/// <remarks>
/// The <c>*Id</c> values only resolve when the host maps them, via <c>FronteggSettings.PermissionIdMappings</c>
/// or a custom <c>IPermissionIdResolver</c>. Without a mapping the numeric claim is never emitted and every
/// <c>permid:</c> gate denies — which is indistinguishable from "the user lacks the permission" unless you know
/// to look. This sample maps <see cref="ReportsDeleteId"/> in <c>appsettings.json</c>.
/// </remarks>
public static class SamplePermissions
{
    /// <summary>Native Frontegg permission key for reading reports. Replace with a key from your tenant.</summary>
    public const string ReportsRead = "sample.reports.read";

    /// <summary>Native Frontegg permission key for deleting reports.</summary>
    public const string ReportsDelete = "sample.reports.delete";

    /// <summary>Numeric id this sample maps to <see cref="ReportsDelete"/>.</summary>
    public const int ReportsDeleteId = 101;

    /// <summary>
    /// Policy requiring <see cref="ReportsRead"/>. Nothing registers it: the package's policy provider
    /// materializes any name starting with <c>perm:</c> on demand. It is a constant only because
    /// <c>RequireAuthorization</c> and <c>[Authorize]</c> want one.
    /// </summary>
    public const string ReportsReadPolicy = "perm:" + ReportsRead;

    /// <summary>Policy requiring the numeric id <see cref="ReportsDeleteId"/>, via the <c>permid:</c> prefix.</summary>
    public const string ReportsDeleteIdPolicy = "permid:101";
}
