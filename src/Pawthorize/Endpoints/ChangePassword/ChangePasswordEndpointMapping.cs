using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.ChangePassword;

/// <summary>
/// Endpoint mapping for ChangePassword feature.
/// </summary>
public static class ChangePasswordEndpointMapping
{
    /// <summary>
    /// Maps the change password endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapChangePassword<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapPost(options.ChangePasswordPath, async (
                ChangePasswordRequest request,
                ChangePasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ChangePassword")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-global");
        }

        return endpoint;
    }
}
