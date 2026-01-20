using System.Linq;
using ErrorHound.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.DTOs;
using Pawthorize.Handlers;
using Pawthorize.Middleware;
using Pawthorize.Models;

namespace Pawthorize.Extensions;

/// <summary>
/// Extension methods for mapping Pawthorize authentication endpoints.
/// </summary>
public static class WebApplicationExtensions
{
    /// <summary>
    /// Configures Pawthorize middleware including ErrorHound, CSRF protection, Rate Limiting, Authentication, and Authorization.
    /// Must be called before MapPawthorize.
    /// </summary>
    /// <param name="app">Web application</param>
    /// <returns>Web application for chaining</returns>
    public static IApplicationBuilder UsePawthorize(this IApplicationBuilder app)
    {
        app.UseErrorHound();

        var options = app.ApplicationServices.GetRequiredService<IOptions<PawthorizeOptions>>().Value;

        // Apply rate limiting middleware if enabled
        if (options.RateLimiting.Enabled)
        {
            app.UseRateLimiter();
        }

        if (options.Csrf.Enabled &&
            (options.TokenDelivery == TokenDeliveryStrategy.Hybrid ||
             options.TokenDelivery == TokenDeliveryStrategy.HttpOnlyCookies))
        {
            app.UseMiddleware<CsrfProtectionMiddleware>();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }
    /// <summary>
    /// Map all Pawthorize authentication endpoints with auto-detected types.
    /// Types are automatically detected from the AddPawthorize call.
    /// </summary>
    /// <param name="app">Web application</param>
    /// <param name="configure">Optional configuration for endpoint paths</param>
    /// <returns>Route group builder for further configuration</returns>
    public static RouteGroupBuilder MapPawthorize(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
    {
        // Retrieve type metadata registered by AddPawthorize
        var metadata = app.Services.GetService<PawthorizeTypeMetadata>();
        if (metadata == null)
        {
            throw new InvalidOperationException(
                "PawthorizeTypeMetadata not found in DI. " +
                "Ensure you've called AddPawthorize<TUser, TRegisterRequest>() before MapPawthorize().");
        }

        // Use reflection to call the generic MapPawthorize method with the correct types
        var methods = typeof(WebApplicationExtensions)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(m => m.Name == nameof(MapPawthorize) && m.IsGenericMethod && m.GetGenericArguments().Length == 2)
            .ToList();

        if (methods.Count == 0)
        {
            throw new InvalidOperationException(
                "Could not find generic MapPawthorize<TUser, TRegisterRequest> method via reflection.");
        }

        var method = methods.First().MakeGenericMethod(metadata.UserType, metadata.RegisterRequestType);
        return (RouteGroupBuilder)method.Invoke(null, new object?[] { app, configure })!;
    }

    /// <summary>
    /// Map all Pawthorize authentication endpoints with configurable paths.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <typeparam name="TRegisterRequest">Registration request type</typeparam>
    /// <param name="app">Web application</param>
    /// <param name="configure">Optional configuration for endpoint paths</param>
    /// <returns>Route group builder for further configuration</returns>
    public static RouteGroupBuilder MapPawthorize<TUser, TRegisterRequest>(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        var options = new PawthorizeEndpointOptions();
        configure?.Invoke(options);

        // Check if OAuth is enabled from metadata
        var metadata = app.Services.GetService<PawthorizeTypeMetadata>();
        var isOAuthEnabled = metadata?.EnableOAuth ?? false;
        var isRateLimitingEnabled = metadata?.RateLimitingEnabled ?? true;

        var group = app.MapGroup(options.BasePath)
            .WithTags("Authentication");

        var loginEndpoint = group.MapPost(options.LoginPath, async (
                LoginRequest request,
                LoginHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Login")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            loginEndpoint.RequireRateLimiting("pawthorize-login");
        }

        var registerEndpoint = group.MapPost(options.RegisterPath, async (
                TRegisterRequest request,
                RegisterHandler<TUser, TRegisterRequest> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Register")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            registerEndpoint.RequireRateLimiting("pawthorize-register");
        }

        var refreshEndpoint = group.MapPost(options.RefreshPath, async (
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
            refreshEndpoint.RequireRateLimiting("pawthorize-refresh");
        }

        var logoutEndpoint = group.MapPost(options.LogoutPath, async (
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
            logoutEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var forgotPasswordEndpoint = group.MapPost(options.ForgotPasswordPath, async (
                ForgotPasswordRequest request,
                ForgotPasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ForgotPassword")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            forgotPasswordEndpoint.RequireRateLimiting("pawthorize-password-reset");
        }

        var resetPasswordEndpoint = group.MapPost(options.ResetPasswordPath, async (
                ResetPasswordRequest request,
                ResetPasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ResetPassword")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            resetPasswordEndpoint.RequireRateLimiting("pawthorize-password-reset");
        }

        var changePasswordEndpoint = group.MapPost(options.ChangePasswordPath, async (
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
            changePasswordEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var setPasswordEndpoint = group.MapPost(options.SetPasswordPath, async (
                SetPasswordRequest request,
                SetPasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("SetPassword")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            setPasswordEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var verifyEmailEndpoint = group.MapPost(options.VerifyEmailPath, async (
                VerifyEmailRequest request,
                VerifyEmailHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("VerifyEmail")
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            verifyEmailEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var getCurrentUserEndpoint = group.MapGet(options.GetCurrentUserPath, async (
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
            getCurrentUserEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var getActiveSessionsEndpoint = group.MapGet(options.GetActiveSessionsPath, async (
                GetActiveSessionsHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(context, ct);
            })
            .WithName("GetActiveSessions")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            getActiveSessionsEndpoint.RequireRateLimiting("pawthorize-global");
        }

        var revokeSessionsEndpoint = group.MapPost(options.RevokeAllOtherSessionsPath, async (
                RevokeAllOtherSessionsRequest? request,
                RevokeAllOtherSessionsHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request ?? new RevokeAllOtherSessionsRequest(), context, ct);
            })
            .WithName("RevokeAllOtherSessions")
            .RequireAuthorization()
            .WithOpenApi();

        if (isRateLimitingEnabled)
        {
            revokeSessionsEndpoint.RequireRateLimiting("pawthorize-global");
        }

        // Auto-map OAuth endpoints if OAuth is enabled
        if (isOAuthEnabled)
        {
            // OAuth Initiate - Redirect user to OAuth provider
            var oauthInitiateEndpoint = group.MapGet(options.OAuthInitiatePath, async (
                    string provider,
                    string? returnUrl,
                    Handlers.OAuthInitiateHandler handler,
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
                    Handlers.OAuthCallbackHandler<TUser> handler,
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
                    Handlers.LinkProviderHandler<TUser> handler,
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
                    Handlers.UnlinkProviderHandler<TUser> handler,
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
                    Handlers.ListLinkedProvidersHandler<TUser> handler,
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

        return group;
    }

    /// <summary>
    /// Map OAuth 2.0 endpoints for external provider authentication.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="app">Web application</param>
    /// <param name="configure">Optional configuration for endpoint paths</param>
    /// <returns>Route group builder for further configuration</returns>
    public static RouteGroupBuilder MapPawthorizeOAuth<TUser>(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
    {
        var options = new PawthorizeEndpointOptions();
        configure?.Invoke(options);

        var group = app.MapGroup(options.BasePath)
            .WithTags("OAuth Authentication");

        // OAuth Initiate - Redirect user to OAuth provider
        group.MapGet(options.OAuthInitiatePath, async (
                string provider,
                string? returnUrl,
                Handlers.OAuthInitiateHandler handler,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, returnUrl, ct);
            })
            .WithName("OAuthInitiate")
            .WithOpenApi();

        // OAuth Callback - Handle OAuth provider callback
        group.MapGet(options.OAuthCallbackPath, async (
                string provider,
                string? code,
                string? state,
                string? error,
                string? error_description,
                Handlers.OAuthCallbackHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, code, state, error, error_description, context, ct);
            })
            .WithName("OAuthCallback")
            .WithOpenApi();

        // Link Provider - Initiate OAuth flow to link provider to authenticated user
        group.MapPost(options.OAuthLinkPath, async (
                string provider,
                string? returnUrl,
                Handlers.LinkProviderHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, returnUrl, context, ct);
            })
            .WithName("LinkOAuthProvider")
            .RequireAuthorization()
            .WithOpenApi();

        // Unlink Provider - Unlink OAuth provider from authenticated user
        group.MapDelete(options.OAuthUnlinkPath, async (
                string provider,
                Handlers.UnlinkProviderHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(provider, context, ct);
            })
            .WithName("UnlinkOAuthProvider")
            .RequireAuthorization()
            .WithOpenApi();

        // List Linked Providers - Get all linked OAuth providers for authenticated user
        group.MapGet(options.OAuthLinkedProvidersPath, async (
                Handlers.ListLinkedProvidersHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(context, ct);
            })
            .WithName("ListLinkedProviders")
            .RequireAuthorization()
            .WithOpenApi();

        return group;
    }

    /// <summary>
    /// Map login endpoint only.
    /// </summary>
    public static RouteHandlerBuilder MapPawthorizeLogin<TUser>(
        this IEndpointRouteBuilder app,
        string path = "/api/auth/login")
        where TUser : class, IAuthenticatedUser
    {
        return app.MapPost(path, async (
                LoginRequest request,
                LoginHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Login")
            .WithTags("Authentication")
            .WithOpenApi();
    }

    /// <summary>
    /// Map register endpoint only.
    /// </summary>
    public static RouteHandlerBuilder MapPawthorizeRegister<TUser, TRegisterRequest>(
        this IEndpointRouteBuilder app,
        string path = "/api/auth/register")
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        return app.MapPost(path, async (
                TRegisterRequest request,
                RegisterHandler<TUser, TRegisterRequest> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Register")
            .WithTags("Authentication")
            .WithOpenApi();
    }

    /// <summary>
    /// Map refresh token endpoint only.
    /// </summary>
    public static RouteHandlerBuilder MapPawthorizeRefresh<TUser>(
        this IEndpointRouteBuilder app,
        string path = "/api/auth/refresh")
        where TUser : class, IAuthenticatedUser
    {
        return app.MapPost(path, async (
                RefreshTokenRequest request,
                RefreshHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("RefreshToken")
            .WithTags("Authentication")
            .WithOpenApi();
    }

    /// <summary>
    /// Map logout endpoint only.
    /// </summary>
    public static RouteHandlerBuilder MapPawthorizeLogout<TUser>(
        this IEndpointRouteBuilder app,
        string path = "/api/auth/logout")
        where TUser : class, IAuthenticatedUser
    {
        return app.MapPost(path, async (
                LogoutRequest request,
                LogoutHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Logout")
            .WithTags("Authentication")
            .WithOpenApi();
    }

    /// <summary>
    /// Map all Pawthorize authentication endpoints with configurable paths.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <typeparam name="TRegisterRequest">Registration request type</typeparam>
    /// <param name="app">Web application</param>
    /// <param name="configure">Optional configuration for endpoint paths</param>
    /// <returns>Route group builder for further configuration</returns>
    [Obsolete("Use MapPawthorize() instead. The generic types are now auto-detected from AddPawthorize<TUser, TRegisterRequest>().")]
    public static RouteGroupBuilder MapPawthorizeEndpoints<TUser, TRegisterRequest>(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        return MapPawthorize<TUser, TRegisterRequest>(app, configure);
    }
}

/// <summary>
/// Configuration options for Pawthorize endpoint paths.
/// </summary>
public class PawthorizeEndpointOptions
{
    /// <summary>
    /// Base path for all authentication endpoints.
    /// Default: "/api/auth"
    /// </summary>
    public string BasePath { get; set; } = "/api/auth";

    /// <summary>
    /// Path for login endpoint (relative to BasePath).
    /// Default: "/login"
    /// Full path: {BasePath}/login
    /// </summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Path for register endpoint (relative to BasePath).
    /// Default: "/register"
    /// Full path: {BasePath}/register
    /// </summary>
    public string RegisterPath { get; set; } = "/register";

    /// <summary>
    /// Path for refresh token endpoint (relative to BasePath).
    /// Default: "/refresh"
    /// Full path: {BasePath}/refresh
    /// </summary>
    public string RefreshPath { get; set; } = "/refresh";

    /// <summary>
    /// Path for logout endpoint (relative to BasePath).
    /// Default: "/logout"
    /// Full path: {BasePath}/logout
    /// </summary>
    public string LogoutPath { get; set; } = "/logout";

    /// <summary>
    /// Path for forgot password endpoint (relative to BasePath).
    /// Default: "/forgot-password"
    /// Full path: {BasePath}/forgot-password
    /// </summary>
    public string ForgotPasswordPath { get; set; } = "/forgot-password";

    /// <summary>
    /// Path for reset password endpoint (relative to BasePath).
    /// Default: "/reset-password"
    /// Full path: {BasePath}/reset-password
    /// </summary>
    public string ResetPasswordPath { get; set; } = "/reset-password";

    /// <summary>
    /// Path for change password endpoint (relative to BasePath).
    /// Default: "/change-password"
    /// Full path: {BasePath}/change-password
    /// </summary>
    public string ChangePasswordPath { get; set; } = "/change-password";

    /// <summary>
    /// Path for set password endpoint (relative to BasePath).
    /// For OAuth-only users to set their initial password.
    /// Default: "/set-password"
    /// Full path: {BasePath}/set-password
    /// </summary>
    public string SetPasswordPath { get; set; } = "/set-password";

    /// <summary>
    /// Path for verify email endpoint (relative to BasePath).
    /// Default: "/verify-email"
    /// Full path: {BasePath}/verify-email
    /// </summary>
    public string VerifyEmailPath { get; set; } = "/verify-email";

    /// <summary>
    /// Path for get current user endpoint (relative to BasePath).
    /// Default: "/me"
    /// Full path: {BasePath}/me
    /// </summary>
    public string GetCurrentUserPath { get; set; } = "/me";

    /// <summary>
    /// Path for get active sessions endpoint (relative to BasePath).
    /// Default: "/sessions"
    /// Full path: {BasePath}/sessions
    /// </summary>
    public string GetActiveSessionsPath { get; set; } = "/sessions";

    /// <summary>
    /// Path for revoke all other sessions endpoint (relative to BasePath).
    /// Default: "/sessions/revoke-others"
    /// Full path: {BasePath}/sessions/revoke-others
    /// </summary>
    public string RevokeAllOtherSessionsPath { get; set; } = "/sessions/revoke-others";

    /// <summary>
    /// Path for OAuth initiate endpoint (relative to BasePath).
    /// Default: "/oauth/{provider}"
    /// Full path: {BasePath}/oauth/{provider}
    /// </summary>
    public string OAuthInitiatePath { get; set; } = "/oauth/{provider}";

    /// <summary>
    /// Path for OAuth callback endpoint (relative to BasePath).
    /// Default: "/oauth/{provider}/callback"
    /// Full path: {BasePath}/oauth/{provider}/callback
    /// </summary>
    public string OAuthCallbackPath { get; set; } = "/oauth/{provider}/callback";

    /// <summary>
    /// Path for OAuth link provider endpoint (relative to BasePath).
    /// Default: "/oauth/{provider}/link"
    /// Full path: {BasePath}/oauth/{provider}/link
    /// </summary>
    public string OAuthLinkPath { get; set; } = "/oauth/{provider}/link";

    /// <summary>
    /// Path for OAuth unlink provider endpoint (relative to BasePath).
    /// Default: "/oauth/{provider}/unlink"
    /// Full path: {BasePath}/oauth/{provider}/unlink
    /// </summary>
    public string OAuthUnlinkPath { get; set; } = "/oauth/{provider}/unlink";

    /// <summary>
    /// Path for list linked providers endpoint (relative to BasePath).
    /// Default: "/oauth/linked"
    /// Full path: {BasePath}/oauth/linked
    /// </summary>
    public string OAuthLinkedProvidersPath { get; set; } = "/oauth/linked";
}