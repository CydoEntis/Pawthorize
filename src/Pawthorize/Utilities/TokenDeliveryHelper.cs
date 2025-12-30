using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Models;
using Pawthorize.Services;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Utilities;

/// <summary>
/// Helper for delivering authentication tokens based on configured strategy.
/// Supports: ResponseBody, HttpOnlyCookies, and Hybrid delivery.
/// </summary>
public static class TokenDeliveryHelper
{
    /// <summary>
    /// Deliver tokens according to the specified strategy.
    /// </summary>
    /// <param name="authResult">Authentication result containing tokens</param>
    /// <param name="httpContext">HTTP context for setting cookies</param>
    /// <param name="strategy">Token delivery strategy</param>
    /// <param name="options">Pawthorize options for CSRF configuration</param>
    /// <param name="csrfService">CSRF token service for generating tokens</param>
    /// <param name="logger">Optional logger for debugging and monitoring</param>
    /// <returns>IResult that will be wrapped by SuccessHound middleware</returns>
    public static IResult DeliverTokens(
        AuthResult authResult,
        HttpContext httpContext,
        TokenDeliveryStrategy strategy,
        PawthorizeOptions options,
        CsrfTokenService? csrfService = null,
        ILogger? logger = null)
    {
        logger?.LogDebug("Delivering tokens using strategy: {Strategy}", strategy);

        try
        {
            var result = strategy switch
            {
                TokenDeliveryStrategy.ResponseBody => DeliverInBody(authResult, httpContext, logger),
                TokenDeliveryStrategy.HttpOnlyCookies => DeliverInCookies(authResult, httpContext, options, csrfService, logger),
                TokenDeliveryStrategy.Hybrid => DeliverHybrid(authResult, httpContext, options, csrfService, logger),
                _ => throw new InvalidOperationException($"Unknown token delivery strategy: {strategy}")
            };

            logger?.LogDebug("Tokens delivered successfully using strategy: {Strategy}", strategy);
            return result;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to deliver tokens using strategy: {Strategy}", strategy);
            throw;
        }
    }

    /// <summary>
    /// Deliver both tokens in response body (JSON).
    /// Uses SuccessHound extension method to wrap the response.
    /// </summary>
    private static IResult DeliverInBody(AuthResult authResult, HttpContext httpContext, ILogger? logger)
    {
        logger?.LogDebug("Delivering access and refresh tokens in response body");
        return authResult.Ok(httpContext);
    }

    /// <summary>
    /// Deliver both tokens in HttpOnly cookies.
    /// Uses SuccessHound extension method to wrap the empty response.
    /// </summary>
    private static IResult DeliverInCookies(
        AuthResult authResult,
        HttpContext httpContext,
        PawthorizeOptions options,
        CsrfTokenService? csrfService,
        ILogger? logger)
    {
        logger?.LogDebug("Delivering access and refresh tokens in HttpOnly cookies");

        SetCookie(httpContext, "access_token", authResult.AccessToken, authResult.AccessTokenExpiresAt, logger);
        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt, logger);

        // Set CSRF token if enabled
        SetCsrfToken(httpContext, options, csrfService, logger);

        logger?.LogDebug("Both tokens set in HttpOnly cookies");

        return new { }.Ok(httpContext);
    }

    /// <summary>
    /// Deliver access token in body, refresh token in HttpOnly cookie (recommended).
    /// Uses SuccessHound extension method to wrap the response.
    /// </summary>
    private static IResult DeliverHybrid(
        AuthResult authResult,
        HttpContext httpContext,
        PawthorizeOptions options,
        CsrfTokenService? csrfService,
        ILogger? logger)
    {
        logger?.LogDebug("Delivering tokens in hybrid mode (access token in body, refresh token in cookie)");

        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt, logger);

        // Set CSRF token if enabled
        SetCsrfToken(httpContext, options, csrfService, logger);

        var hybridResult = new AuthResult
        {
            AccessToken = authResult.AccessToken,
            RefreshToken = null,
            AccessTokenExpiresAt = authResult.AccessTokenExpiresAt,
            RefreshTokenExpiresAt = authResult.RefreshTokenExpiresAt,
            TokenType = authResult.TokenType
        };

        logger?.LogDebug("Hybrid token delivery completed");

        return hybridResult.Ok(httpContext);
    }

    /// <summary>
    /// Set an HttpOnly cookie with security flags.
    /// </summary>
    private static void SetCookie(HttpContext context, string name, string value, DateTime expires, ILogger? logger)
    {
        logger?.LogDebug("Setting HttpOnly cookie: {CookieName}, Expires: {ExpiresAt}", name, expires);

        context.Response.Cookies.Append(name, value, new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps, // Only require HTTPS in production
            SameSite = SameSiteMode.Strict,
            Expires = expires
        });

        logger?.LogDebug("Cookie set successfully: {CookieName}", name);
    }

    /// <summary>
    /// Set CSRF token cookie and response header.
    /// Cookie is NOT HttpOnly so JavaScript can read it for inclusion in request headers.
    /// </summary>
    private static void SetCsrfToken(
        HttpContext context,
        PawthorizeOptions options,
        CsrfTokenService? csrfService,
        ILogger? logger)
    {
        // Skip if CSRF is disabled or service not provided
        if (!options.Csrf.Enabled || csrfService == null)
        {
            logger?.LogDebug("CSRF protection is disabled or service not available, skipping CSRF token");
            return;
        }

        logger?.LogDebug("Generating and setting CSRF token");

        var csrfToken = csrfService.GenerateToken();
        var expiresAt = DateTime.UtcNow.AddMinutes(options.Csrf.TokenLifetimeMinutes);

        // Set CSRF cookie (NOT HttpOnly so JS can read it)
        context.Response.Cookies.Append(options.Csrf.CookieName, csrfToken, new CookieOptions
        {
            HttpOnly = false, // JS needs to read this
            Secure = context.Request.IsHttps, // Only require HTTPS in production
            SameSite = SameSiteMode.Strict,
            Expires = expiresAt
        });

        // Also set in response header for SPAs
        context.Response.Headers.Append(options.Csrf.HeaderName, csrfToken);

        logger?.LogDebug("CSRF token set in cookie '{CookieName}' and header '{HeaderName}'",
            options.Csrf.CookieName, options.Csrf.HeaderName);
    }

    /// <summary>
    /// Clear authentication cookies (used during logout).
    /// </summary>
    public static void ClearAuthCookies(
        HttpContext context,
        TokenDeliveryStrategy strategy,
        PawthorizeOptions options,
        ILogger? logger = null)
    {
        logger?.LogDebug("Clearing authentication cookies for strategy: {Strategy}", strategy);

        if (strategy == TokenDeliveryStrategy.ResponseBody)
        {
            logger?.LogDebug("Strategy is ResponseBody, no cookies to clear");
            return;
        }

        context.Response.Cookies.Delete("refresh_token");
        logger?.LogDebug("Refresh token cookie deleted");

        if (strategy == TokenDeliveryStrategy.HttpOnlyCookies)
        {
            context.Response.Cookies.Delete("access_token");
            logger?.LogDebug("Access token cookie deleted");
        }

        // Clear CSRF cookie if enabled
        if (options.Csrf.Enabled)
        {
            context.Response.Cookies.Delete(options.Csrf.CookieName);
            logger?.LogDebug("CSRF cookie '{CookieName}' deleted", options.Csrf.CookieName);
        }

        logger?.LogDebug("Authentication cookies cleared successfully");
    }
}