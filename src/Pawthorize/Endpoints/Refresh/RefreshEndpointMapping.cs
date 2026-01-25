using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.Refresh;

/// <summary>
/// Endpoint mapping for Refresh feature.
/// </summary>
public static class RefreshEndpointMapping
{
    /// <summary>
    /// Maps the refresh token endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapRefresh<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapPost(options.RefreshPath, async (
                RefreshTokenRequest request,
                RefreshHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("RefreshToken")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-refresh");
        }

        return endpoint;
    }
}
