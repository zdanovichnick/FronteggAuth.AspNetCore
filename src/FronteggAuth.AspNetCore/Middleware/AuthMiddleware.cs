using FronteggAuth.AspNetCore.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace FronteggAuth.AspNetCore.Middleware;

/// <summary>
/// Gates the request pipeline: skips CORS preflight, OIDC callbacks, unmatched routes, and anonymous endpoints; challenges
/// interactive (browser) requests via OpenID Connect and returns 401 for unauthenticated API/token requests;
/// and annotates the response with a <c>bearer</c> header indicating the authentication style.
/// </summary>
public sealed class AuthMiddleware(RequestDelegate next, IOptions<FronteggSettings> options)
{
    private readonly FronteggSettings _options = options.Value;

    /// <summary>Executes the gating logic for the current request.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            await next(context);
            return;
        }

        var path = context.Request.Path;
        if (path.StartsWithSegments("/signin-oidc") || path.StartsWithSegments("/signout-callback-oidc"))
        {
            await next(context);
            return;
        }

        var endpoint = context.GetEndpoint();
        if (endpoint is null)
        {
            await next(context);
            return;
        }

        if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var apiKeyAuth = context.Request.Headers.ContainsKey(_options.ApiKeyHeaderName);
        var bearerAuth = !apiKeyAuth &&
            (context.Request.Headers.Authorization.FirstOrDefault()?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ?? false);
        var isTokenRequest = apiKeyAuth || bearerAuth;
        var isAuthenticated = context.User.Identity?.IsAuthenticated == true;

        if (!isAuthenticated)
        {
            if (!isTokenRequest && _options.EnableOpenIdConnect && AcceptsHtml(context.Request))
            {
                await context.ChallengeAsync(FronteggAuthSchemes.OpenIdConnect);
                return;
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Response.Headers.Append("bearer", isTokenRequest ? "true" : "false");
        await next(context);
    }

    internal static bool AcceptsHtml(HttpRequest request)
        => request.Headers.Accept.Any(v => v is not null && v.Contains("text/html", StringComparison.OrdinalIgnoreCase));
}
