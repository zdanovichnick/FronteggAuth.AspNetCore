using FronteggAuth.AspNetCore.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace FronteggAuth.AspNetCore.Authorization;

/// <summary>Shared guard logic for the MVC authorization filters in this package.</summary>
internal static class AuthorizationFilterGuards
{
    /// <summary>Whether the endpoint opts out of package authorization via <c>[AllowAnonymous]</c> or <see cref="SkipAuthAttribute"/>.</summary>
    public static bool ShouldSkip(AuthorizationFilterContext context)
    {
        var endpoint = context.HttpContext.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            return true;
        if (endpoint?.Metadata.GetMetadata<SkipAuthAttribute>() is not null)
            return true;

        return context.Filters.Any(f => f is SkipAuthAttribute);
    }

    /// <summary>403 response with an RFC 7807 problem payload.</summary>
    public static IActionResult Forbidden(string detail) =>
        new ObjectResult(new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = "Forbidden",
            Detail = detail
        })
        {
            StatusCode = StatusCodes.Status403Forbidden
        };

    /// <summary>
    /// Runs the checks common to all permission/role filters: authentication and account status.
    /// Returns the deny <see cref="IActionResult"/>, or <c>null</c> when access is permitted.
    /// </summary>
    public static IActionResult? CheckCommon(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true)
            return new UnauthorizedResult();

        var statusValidator = context.HttpContext.RequestServices.GetService<IAccountStatusValidator>();
        if (statusValidator is not null && !statusValidator.HasAccess(user.Claims.ToList()))
            return Forbidden("Account status does not permit access.");

        return null;
    }
}
