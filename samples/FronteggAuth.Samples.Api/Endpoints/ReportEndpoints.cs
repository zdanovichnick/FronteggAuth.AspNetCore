using FronteggAuth.AspNetCore.Models;

namespace FronteggAuth.Samples.Api.Endpoints;

/// <summary>
/// The part of the sample that looks like an actual API: three endpoints, each gated a different way. This is
/// the surface to copy from — the diagnostics endpoints next door exist to explain what happened here.
/// </summary>
public static class ReportEndpoints
{
    /// <summary>Maps the report endpoints onto <paramref name="app"/>.</summary>
    public static IEndpointRouteBuilder MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        var reports = app.MapGroup("/api/reports");

        // Gated on a native Frontegg permission key. Nothing registers "perm:sample.reports.read" — the
        // package's policy provider materializes any policy name with that prefix on demand, so a permission
        // added in the Frontegg portal is usable here the moment you reference it.
        reports.MapGet("/", () => new[]
            {
                new Report(1, "Q3 revenue"),
                new Report(2, "Churn by cohort"),
            })
            .RequireAuthorization(SamplePermissions.ReportsReadPolicy)
            .WithName("ListReports");

        // Gated on the numeric representation of a permission instead. Same mechanism, "permid:" prefix, and it
        // only resolves because appsettings.json maps 101 to sample.reports.delete. Reach for this when a legacy
        // system already identifies permissions by number; prefer the key form in new code.
        reports.MapDelete("/{id:int}", (int id) => TypedResults.Ok(new Deleted(id)))
            .RequireAuthorization(SamplePermissions.ReportsDeleteIdPolicy)
            .WithName("DeleteReport");

        // No permission involved — an ordinary role requirement, built inline. IsInRole resolves against the role
        // claim type the package configures from FronteggSettings:ClaimTypeNames:Role, so this keeps working if
        // your tenant emits roles under a non-standard claim.
        reports.MapGet("/admin-summary", () => new AdminSummary(TotalReports: 2, ArchivedReports: 0))
            .RequireAuthorization(policy => policy.RequireRole(FronteggRoles.Admin))
            .WithName("ReportAdminSummary");

        return app;
    }

    private sealed record Report(int Id, string Title);

    private sealed record Deleted(int Id);

    private sealed record AdminSummary(int TotalReports, int ArchivedReports);
}
