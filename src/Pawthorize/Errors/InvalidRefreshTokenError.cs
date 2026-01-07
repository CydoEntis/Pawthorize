using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when refresh token is invalid or expired.
/// Returns 401 Unauthorized.
/// </summary>
public sealed class InvalidRefreshTokenError : ApiError
{
    /// <summary>
    /// Creates a generic invalid refresh token error.
    /// </summary>
    public InvalidRefreshTokenError()
        : base(
            code: "INVALID_REFRESH_TOKEN",
            message: "Refresh token is invalid or expired",
            status: (int)HttpStatusCode.Unauthorized,
            details: null)
    {
    }

    /// <summary>
    /// Creates an invalid refresh token error with specific reason and actionable hints.
    /// </summary>
    /// <param name="reason">The specific reason for token validation failure.</param>
    /// <param name="tokenDeliveryMode">The token delivery mode being used (Hybrid, HttpOnlyCookies, ResponseBody).</param>
    public InvalidRefreshTokenError(string reason, string tokenDeliveryMode)
        : base(
            code: "INVALID_REFRESH_TOKEN",
            message: "Refresh token is invalid or expired",
            status: (int)HttpStatusCode.Unauthorized,
            details: new
            {
                reason,
                tokenDeliveryMode,
                hint = GetHintForReason(reason, tokenDeliveryMode),
                action = GetActionForReason(reason),
                documentation = "Refresh tokens are single-use and expire after 7 days (configurable). When a refresh token is used, it's revoked and a new one is issued. Tokens are automatically rotated on each refresh for security."
            })
    {
    }

    private static string GetHintForReason(string reason, string tokenDeliveryMode)
    {
        return reason switch
        {
            var r when r.Contains("not found") || r.Contains("not exist") || r.Contains("revoked") =>
                tokenDeliveryMode == "ResponseBody"
                    ? "The refresh token was not found in the database. This could mean it was already used (tokens are single-use), was revoked, or never existed. The user needs to log in again."
                    : "The refresh token was not found in the database. This could mean it was already used (tokens are single-use), was revoked, or never existed. Check that the refresh token cookie is being sent with the request.",

            var r when r.Contains("expired") =>
                "The refresh token has exceeded its lifetime. Refresh tokens expire after the configured duration (default: 7 days). The user needs to log in again to get a new refresh token.",

            var r when r.Contains("missing") || r.Contains("not provided") =>
                tokenDeliveryMode == "ResponseBody"
                    ? "No refresh token was provided in the request body. Include the refresh token in the 'refreshToken' field of your POST request."
                    : "No refresh token was found in cookies or request body. Ensure cookies are being sent with the request (credentials: 'include' in fetch) or provide the token in the request body.",

            var r when r.Contains("user") || r.Contains("User") =>
                "The user associated with this refresh token no longer exists. This usually means the user account was deleted. Clear the authentication state and redirect to login.",

            _ => "The refresh token is invalid. The user needs to log in again to get a new refresh token."
        };
    }

    private static string GetActionForReason(string reason)
    {
        return reason switch
        {
            var r when r.Contains("expired") => "Redirect user to login page",
            var r when r.Contains("missing") || r.Contains("not provided") => "Ensure refresh token is included in request",
            var r when r.Contains("user") || r.Contains("User") => "Clear auth state and redirect to login",
            _ => "Clear auth cookies/storage and redirect user to login"
        };
    }
}