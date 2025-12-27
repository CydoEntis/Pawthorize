using ErrorHound.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.Core.Abstractions;
using SuccessHound.Extensions;

namespace Pawthorize.AspNetCore.Extensions;

/// <summary>
/// Extension methods for mapping Pawthorize authentication endpoints.
/// </summary>
public static class WebApplicationExtensions
{
    /// <summary>
    /// Wire Pawthorize middleware in the correct order.
    /// This sets up ErrorHound, Authentication, and Authorization.
    /// Must be called before MapPawthorizeEndpoints.
    /// Note: SuccessHound formatting happens automatically via extension methods, no middleware needed.
    /// </summary>
    /// <param name="app">Web application</param>
    /// <returns>Web application for chaining</returns>
    public static IApplicationBuilder UsePawthorize(this IApplicationBuilder app)
    {
        app.UseErrorHound();

        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }
    /// <summary>
    /// Map all Pawthorize authentication endpoints with configurable paths.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <typeparam name="TRegisterRequest">Registration request type</typeparam>
    /// <param name="app">Web application</param>
    /// <param name="configure">Optional configuration for endpoint paths</param>
    /// <returns>Route group builder for further configuration</returns>
    public static RouteGroupBuilder MapPawthorizeEndpoints<TUser, TRegisterRequest>(
        this WebApplication app,
        Action<PawthorizeEndpointOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        var options = new PawthorizeEndpointOptions();
        configure?.Invoke(options);

        var group = app.MapGroup(options.BasePath)
            .WithTags("Authentication");

        group.MapPost(options.LoginPath, async (
                LoginRequest request,
                LoginHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Login")
            .WithOpenApi();

        group.MapPost(options.RegisterPath, async (
                TRegisterRequest request,
                RegisterHandler<TUser, TRegisterRequest> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Register")
            .WithOpenApi();

        group.MapPost(options.RefreshPath, async (
                RefreshTokenRequest request,
                RefreshHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("RefreshToken")
            .WithOpenApi();

        group.MapPost(options.LogoutPath, async (
                LogoutRequest request,
                LogoutHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("Logout")
            .WithOpenApi();

        group.MapPost(options.ForgotPasswordPath, async (
                ForgotPasswordRequest request,
                ForgotPasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ForgotPassword")
            .WithOpenApi();

        group.MapPost(options.ResetPasswordPath, async (
                ResetPasswordRequest request,
                ResetPasswordHandler<TUser> handler,
                HttpContext context,
                CancellationToken ct) =>
            {
                return await handler.HandleAsync(request, context, ct);
            })
            .WithName("ResetPassword")
            .WithOpenApi();

        group.MapPost(options.ChangePasswordPath, async (
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
}