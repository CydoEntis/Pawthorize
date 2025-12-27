using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Core.Models;
using SuccessHound.AspNetExtensions; 

namespace Pawthorize.AspNetCore.Utilities;

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
    /// <param name="logger">Optional logger for debugging and monitoring</param>
    /// <returns>IResult that will be wrapped by SuccessHound middleware</returns>
    public static IResult DeliverTokens(
        AuthResult authResult,
        HttpContext httpContext,
        TokenDeliveryStrategy strategy,
        ILogger? logger = null)
    {
        logger?.LogDebug("Delivering tokens using strategy: {Strategy}", strategy);

        try
        {
            var result = strategy switch
            {
                TokenDeliveryStrategy.ResponseBody => DeliverInBody(authResult, httpContext, logger),
                TokenDeliveryStrategy.HttpOnlyCookies => DeliverInCookies(authResult, httpContext, logger),
                TokenDeliveryStrategy.Hybrid => DeliverHybrid(authResult, httpContext, logger),
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
    private static IResult DeliverInCookies(AuthResult authResult, HttpContext httpContext, ILogger? logger)
    {
        logger?.LogDebug("Delivering access and refresh tokens in HttpOnly cookies");

        SetCookie(httpContext, "access_token", authResult.AccessToken, authResult.AccessTokenExpiresAt, logger);
        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt, logger);

        logger?.LogDebug("Both tokens set in HttpOnly cookies");

        return new { }.Ok(httpContext);
    }

    /// <summary>
    /// Deliver access token in body, refresh token in HttpOnly cookie (recommended).
    /// Uses SuccessHound extension method to wrap the response.
    /// </summary>
    private static IResult DeliverHybrid(AuthResult authResult, HttpContext httpContext, ILogger? logger)
    {
        logger?.LogDebug("Delivering tokens in hybrid mode (access token in body, refresh token in cookie)");

        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt, logger);

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
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = expires
        });

        logger?.LogDebug("Cookie set successfully: {CookieName}", name);
    }

    /// <summary>
    /// Clear authentication cookies (used during logout).
    /// </summary>
    public static void ClearAuthCookies(HttpContext context, TokenDeliveryStrategy strategy, ILogger? logger = null)
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

        logger?.LogDebug("Authentication cookies cleared successfully");
    }
}