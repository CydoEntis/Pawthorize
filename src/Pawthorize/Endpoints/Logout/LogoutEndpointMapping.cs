using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.Logout;

/// <summary>
/// Endpoint mapping for Logout feature.
/// </summary>
public static class LogoutEndpointMapping
{
    /// <summary>
    /// Maps the logout endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapLogout<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapPost(options.LogoutPath, async (
                LogoutRequest request,
                LogoutHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Logout")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-global");
        }

        return endpoint;
    }
}
