using System.Linq;
using ErrorHound.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
// Type aliases for cleaner code
using ChangeEmail = Pawthorize.Endpoints.ChangeEmail;
using ChangePassword = Pawthorize.Endpoints.ChangePassword;
using ForgotPassword = Pawthorize.Endpoints.ForgotPassword;
using Login = Pawthorize.Endpoints.Login;
using Logout = Pawthorize.Endpoints.Logout;
using OAuth = Pawthorize.Endpoints.OAuth;
using Refresh = Pawthorize.Endpoints.Refresh;
using Register = Pawthorize.Endpoints.Register;
using ResetPassword = Pawthorize.Endpoints.ResetPassword;
using Sessions = Pawthorize.Endpoints.Sessions;
using SetPassword = Pawthorize.Endpoints.SetPassword;
using User = Pawthorize.Endpoints.User;
using VerifyEmail = Pawthorize.Endpoints.VerifyEmail;
// Namespace imports for extension methods
using Pawthorize.Endpoints.ChangeEmail;
using Pawthorize.Endpoints.ChangePassword;
using Pawthorize.Endpoints.ForgotPassword;
using Pawthorize.Endpoints.Login;
using Pawthorize.Endpoints.Logout;
using Pawthorize.Endpoints.OAuth;
using Pawthorize.Endpoints.Refresh;
using Pawthorize.Endpoints.Register;
using Pawthorize.Endpoints.ResetPassword;
using Pawthorize.Endpoints.Sessions;
using Pawthorize.Endpoints.SetPassword;
using Pawthorize.Endpoints.User;
using Pawthorize.Endpoints.VerifyEmail;
using Pawthorize.Internal;
using Pawthorize.Middleware;

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
        where TRegisterRequest : Register.RegisterRequest
    {
        var options = new PawthorizeEndpointOptions();
        configure?.Invoke(options);

        // Check if OAuth is enabled from metadata
        var metadata = app.Services.GetService<PawthorizeTypeMetadata>();
        var isOAuthEnabled = metadata?.EnableOAuth ?? false;
        var isRateLimitingEnabled = metadata?.RateLimitingEnabled ?? true;

        var group = app.MapGroup(options.BasePath)
            .WithTags("Authentication");

        // Map all endpoints using their feature-specific mapping methods
        group.MapLogin<TUser>(options, isRateLimitingEnabled);
        group.MapRegister<TUser, TRegisterRequest>(options, isRateLimitingEnabled);
        group.MapRefresh<TUser>(options, isRateLimitingEnabled);
        group.MapLogout<TUser>(options, isRateLimitingEnabled);
        group.MapForgotPassword<TUser>(options, isRateLimitingEnabled);
        group.MapResetPassword<TUser>(options, isRateLimitingEnabled);
        group.MapChangePassword<TUser>(options, isRateLimitingEnabled);
        group.MapSetPassword<TUser>(options, isRateLimitingEnabled);
        group.MapVerifyEmail<TUser>(options, isRateLimitingEnabled);
        group.MapChangeEmail<TUser>(options, isRateLimitingEnabled);
        group.MapVerifyEmailChange<TUser>(options, isRateLimitingEnabled);
        group.MapGetCurrentUser<TUser>(options, isRateLimitingEnabled);
        group.MapGetActiveSessions<TUser>(options, isRateLimitingEnabled);
        group.MapRevokeSession<TUser>(options, isRateLimitingEnabled);
        group.MapRevokeAllOtherSessions<TUser>(options, isRateLimitingEnabled);

        // Auto-map OAuth endpoints if OAuth is enabled
        if (isOAuthEnabled)
        {
            group.MapOAuthEndpoints<TUser>(options, isRateLimitingEnabled);
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

        // Check if rate limiting is enabled from metadata
        var metadata = app.Services.GetService<PawthorizeTypeMetadata>();
        var isRateLimitingEnabled = metadata?.RateLimitingEnabled ?? true;

        // Map OAuth endpoints using feature-specific mapping
        group.MapOAuthEndpoints<TUser>(options, isRateLimitingEnabled);

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
                Login.LoginRequest request,
                Login.LoginHandler<TUser> handler,
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
        where TRegisterRequest : Register.RegisterRequest
    {
        return app.MapPost(path, async (
                TRegisterRequest request,
                Register.RegisterHandler<TUser, TRegisterRequest> handler,
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
                Refresh.RefreshTokenRequest request,
                Refresh.RefreshHandler<TUser> handler,
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
                Logout.LogoutRequest request,
                Logout.LogoutHandler<TUser> handler,
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
    [Obsolete(
        "Use MapPawthorize() instead. The generic types are now auto-detected from AddPawthorize<TUser, TRegisterRequest>().")]
    public static RouteGroupBuilder MapPawthorizeEndpoints<TUser, TRegisterRequest>(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : Register.RegisterRequest
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
    /// Path for change email endpoint (relative to BasePath).
    /// Default: "/change-email"
    /// Full path: {BasePath}/change-email
    /// </summary>
    public string ChangeEmailPath { get; set; } = "/change-email";

    /// <summary>
    /// Path for verify email change endpoint (relative to BasePath).
    /// Default: "/verify-email-change"
    /// Full path: {BasePath}/verify-email-change
    /// </summary>
    public string VerifyEmailChangePath { get; set; } = "/verify-email-change";

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
    /// Path for revoke specific session endpoint (relative to BasePath).
    /// Default: "/sessions/revoke"
    /// Full path: {BasePath}/sessions/revoke
    /// </summary>
    public string RevokeSessionPath { get; set; } = "/sessions/revoke";

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