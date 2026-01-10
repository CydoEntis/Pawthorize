using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace Pawthorize.Extensions;

/// <summary>
/// Extension methods for applying Pawthorize rate limiting policies to custom endpoints.
/// </summary>
public static class PawthorizeRateLimitingExtensions
{
    /// <summary>
    /// Apply a Pawthorize rate limiting policy to a custom endpoint.
    /// This allows you to reuse Pawthorize's rate limiting policies on your own endpoints.
    /// </summary>
    /// <param name="builder">Route handler builder</param>
    /// <param name="policy">The Pawthorize rate limiting policy to apply</param>
    /// <returns>Route handler builder for chaining</returns>
    /// <example>
    /// <code>
    /// app.MapPost("/api/custom/verify-otp", handler)
    ///     .RequirePawthorizeRateLimit(PawthorizeRateLimitPolicy.Login);
    /// </code>
    /// </example>
    public static RouteHandlerBuilder RequirePawthorizeRateLimit(
        this RouteHandlerBuilder builder,
        PawthorizeRateLimitPolicy policy)
    {
        var policyName = policy switch
        {
            PawthorizeRateLimitPolicy.Global => "pawthorize-global",
            PawthorizeRateLimitPolicy.Login => "pawthorize-login",
            PawthorizeRateLimitPolicy.Register => "pawthorize-register",
            PawthorizeRateLimitPolicy.PasswordReset => "pawthorize-password-reset",
            PawthorizeRateLimitPolicy.Refresh => "pawthorize-refresh",
            PawthorizeRateLimitPolicy.OAuth => "pawthorize-oauth",
            _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, "Unknown rate limit policy")
        };

        return builder.RequireRateLimiting(policyName);
    }

    /// <summary>
    /// Apply a Pawthorize rate limiting policy to a route group.
    /// This allows you to apply rate limiting to all endpoints in a group.
    /// </summary>
    /// <param name="builder">Route group builder</param>
    /// <param name="policy">The Pawthorize rate limiting policy to apply</param>
    /// <returns>Route group builder for chaining</returns>
    /// <example>
    /// <code>
    /// var customAuthGroup = app.MapGroup("/api/custom-auth")
    ///     .RequirePawthorizeRateLimit(PawthorizeRateLimitPolicy.Login);
    /// </code>
    /// </example>
    public static RouteGroupBuilder RequirePawthorizeRateLimit(
        this RouteGroupBuilder builder,
        PawthorizeRateLimitPolicy policy)
    {
        var policyName = policy switch
        {
            PawthorizeRateLimitPolicy.Global => "pawthorize-global",
            PawthorizeRateLimitPolicy.Login => "pawthorize-login",
            PawthorizeRateLimitPolicy.Register => "pawthorize-register",
            PawthorizeRateLimitPolicy.PasswordReset => "pawthorize-password-reset",
            PawthorizeRateLimitPolicy.Refresh => "pawthorize-refresh",
            PawthorizeRateLimitPolicy.OAuth => "pawthorize-oauth",
            _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, "Unknown rate limit policy")
        };

        return builder.RequireRateLimiting(policyName);
    }
}

/// <summary>
/// Pawthorize rate limiting policies available for use on custom endpoints.
/// These policies are automatically configured when you call AddPawthorize.
/// </summary>
public enum PawthorizeRateLimitPolicy
{
    /// <summary>
    /// General protection policy.
    /// Default: 100 requests per minute per IP.
    /// Use for: General authenticated endpoints.
    /// </summary>
    Global,

    /// <summary>
    /// Strict rate limiting for login-like operations.
    /// Default: 5 requests per 5 minutes per IP.
    /// Use for: Login, authentication, or credential verification endpoints.
    /// Prevents: Brute force attacks.
    /// </summary>
    Login,

    /// <summary>
    /// Moderate rate limiting for registration-like operations.
    /// Default: 3 requests per 15 minutes per IP.
    /// Use for: Registration, account creation, or signup endpoints.
    /// Prevents: Spam and bot registrations.
    /// </summary>
    Register,

    /// <summary>
    /// Moderate rate limiting for password reset operations.
    /// Default: 3 requests per 15 minutes per IP.
    /// Use for: Password reset, forgot password, or account recovery endpoints.
    /// Prevents: Account enumeration and spam.
    /// </summary>
    PasswordReset,

    /// <summary>
    /// Lenient rate limiting for token refresh operations.
    /// Default: 50 requests per 5 minutes per IP.
    /// Use for: Token refresh or session extension endpoints.
    /// Note: Higher limit to accommodate normal usage patterns.
    /// </summary>
    Refresh,

    /// <summary>
    /// Moderate rate limiting for OAuth operations.
    /// Default: 10 requests per 5 minutes per IP.
    /// Use for: OAuth initiation, callbacks, or provider linking endpoints.
    /// Prevents: OAuth flow abuse.
    /// </summary>
    OAuth
}
