using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Core.Errors;

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
    /// Creates an invalid refresh token error with custom details.
    /// </summary>
    /// <param name="details">Additional error details.</param>
    public InvalidRefreshTokenError(string details)
        : base(
            code: "INVALID_REFRESH_TOKEN",
            message: "Refresh token is invalid or expired",
            status: (int)HttpStatusCode.Unauthorized,
            details: details)
    {
    }
}