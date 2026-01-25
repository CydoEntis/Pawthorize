using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.Abstractions;
using Pawthorize.Extensions;

namespace Pawthorize.Endpoints.OAuth;

/// <summary>
/// Endpoint mapping for OAuth feature.
/// </summary>
public static class OAuthEndpointMapping
{
    /// <summary>
    /// Maps all OAuth endpoints to the route group.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="group">Route group builder</param>
    /// <param name="options">Endpoint path options</param>
    /// <param name="isRateLimitingEnabled">Whether rate limiting is enabled</param>
    public static void MapOAuthEndpoints<TUser>(
        this RouteGroupBuilder group,
        PawthorizeEndpointOptions options,
        bool isRateLimitingEnabled)
        where TUser : class, IAuthenticatedUser
    {
        // OAuth Initiate - Redirect user to OAuth provider
        var oauthInitiateEndpoint = group.MapGet(options.OAuthInitiatePath, async (
                string provider,
                string? returnUrl,
                OAuthInitiateHandler handler,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, returnUrl, ct);
            })
            .WithName("OAuthInitiate")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            oauthInitiateEndpoint.RequireRateLimiting("pawthorize-oauth");
        }

        // OAuth Callback - Handle OAuth provider callback
        var oauthCallbackEndpoint = group.MapGet(options.OAuthCallbackPath, async (
                string provider,
                string? code,
                string? state,
                string? error,
                string? error_description,
                OAuthCallbackHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, code, state, error, error_description, context, ct);
            })
            .WithName("OAuthCallback")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            oauthCallbackEndpoint.RequireRateLimiting("pawthorize-oauth");
        }

        // Link Provider - Initiate OAuth flow to link provider to authenticated user
        var linkProviderEndpoint = group.MapPost(options.OAuthLinkPath, async (
                string provider,
                string? returnUrl,
                LinkProviderHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, returnUrl, context, ct);
            })
            .WithName("LinkOAuthProvider")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            linkProviderEndpoint.RequireRateLimiting("pawthorize-oauth");
        }

        // Unlink Provider - Unlink OAuth provider from authenticated user
        var unlinkProviderEndpoint = group.MapDelete(options.OAuthUnlinkPath, async (
                string provider,
                UnlinkProviderHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, context, ct);
            })
            .WithName("UnlinkOAuthProvider")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            unlinkProviderEndpoint.RequireRateLimiting("pawthorize-global");
        }

        // List Linked Providers - Get all linked OAuth providers for authenticated user
        var listLinkedProvidersEndpoint = group.MapGet(options.OAuthLinkedProvidersPath, async (
                ListLinkedProvidersHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(context, ct);
            })
            .WithName("ListLinkedProviders")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            listLinkedProvidersEndpoint.RequireRateLimiting("pawthorize-global");
        }
    }
}
