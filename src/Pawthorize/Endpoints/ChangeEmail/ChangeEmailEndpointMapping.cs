using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.ChangeEmail;

/// <summary>
/// Endpoint mapping for ChangeEmail feature.
/// </summary>
public static class ChangeEmailEndpointMapping
{
    /// <summary>
    /// Maps the change email endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapChangeEmail<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapPost(options.ChangeEmailPath, async (
                ChangeEmailRequest request,
                ChangeEmailHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ChangeEmail")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-global");
        }

        return endpoint;
    }

    /// <summary>
    /// Maps the verify email change endpoint to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    /// <returns>The mapped endpoint for further configuration</returns>
    public static RouteHandlerBuilder MapVerifyEmailChange<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : IAuthenticatedUser
    {
        var endpoint = group.MapGet(options.VerifyEmailChangePath, async (
                string token,
                VerifyEmailChangeHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(token, context, ct);
            })
            .WithName("VerifyEmailChange")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            endpoint.RequireRateLimiting("pawthorize-global");
        }

        return endpoint;
    }
}
