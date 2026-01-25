using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.User;

/// <summary>
/// Endpoint mapping for User feature.
/// </summary>
public static class UserEndpointMapping
{
    /// <summary>
    /// Maps the get current user endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapGetCurrentUser<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapGet(options.GetCurrentUserPath, async (
                GetCurrentUserHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(context, ct);
            })
            .WithName("GetCurrentUser")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-global");
        }

        return endpoint;
    }
}
