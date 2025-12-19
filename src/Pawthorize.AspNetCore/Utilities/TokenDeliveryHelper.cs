using Microsoft.AspNetCore.Http;
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
    /// <returns>IResult wrapped with SuccessHound</returns>
    public static IResult DeliverTokens(
        AuthResult authResult,
        HttpContext httpContext,
        TokenDeliveryStrategy strategy)
    {
        return strategy switch
        {
            TokenDeliveryStrategy.ResponseBody => DeliverInBody(authResult),
            TokenDeliveryStrategy.HttpOnlyCookies => DeliverInCookies(authResult, httpContext),
            TokenDeliveryStrategy.Hybrid => DeliverHybrid(authResult, httpContext),
            _ => throw new InvalidOperationException($"Unknown token delivery strategy: {strategy}")
        };
    }

    /// <summary>
    /// Deliver both tokens in response body (JSON).
    /// </summary>
    private static IResult DeliverInBody(AuthResult authResult)
    {
        return authResult.Ok();
    }

    /// <summary>
    /// Deliver both tokens in HttpOnly cookies.
    /// </summary>
    private static IResult DeliverInCookies(AuthResult authResult, HttpContext httpContext)
    {
        SetCookie(httpContext, "access_token", authResult.AccessToken, authResult.AccessTokenExpiresAt);
        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt);

        return new { }.Ok();
    }

    /// <summary>
    /// Deliver access token in body, refresh token in HttpOnly cookie (recommended).
    /// </summary>
    private static IResult DeliverHybrid(AuthResult authResult, HttpContext httpContext)
    {
        SetCookie(httpContext, "refresh_token", authResult.RefreshToken!, authResult.RefreshTokenExpiresAt);

        var hybridResult = new AuthResult
        {
            AccessToken = authResult.AccessToken,
            RefreshToken = null, 
            AccessTokenExpiresAt = authResult.AccessTokenExpiresAt,
            RefreshTokenExpiresAt = authResult.RefreshTokenExpiresAt,
            TokenType = authResult.TokenType
        };

        return hybridResult.Ok();
    }

    /// <summary>
    /// Set an HttpOnly cookie with security flags.
    /// </summary>
    private static void SetCookie(HttpContext context, string name, string value, DateTime expires)
    {
        context.Response.Cookies.Append(name, value, new CookieOptions
        {
            HttpOnly = true, 
            Secure = true, 
            SameSite = SameSiteMode.Strict, 
            Expires = expires
        });
    }

    /// <summary>
    /// Clear authentication cookies (used during logout).
    /// </summary>
    public static void ClearAuthCookies(HttpContext context, TokenDeliveryStrategy strategy)
    {
        if (strategy == TokenDeliveryStrategy.ResponseBody)
        {
            return; 
        }

        context.Response.Cookies.Delete("refresh_token");

        if (strategy == TokenDeliveryStrategy.HttpOnlyCookies)
        {
            context.Response.Cookies.Delete("access_token");
        }
    }
}