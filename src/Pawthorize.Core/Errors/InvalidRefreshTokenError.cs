using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Core.Errors;

/// <summary>
/// Error thrown when refresh token is invalid or expired.
/// Returns 401 Unauthorized.
/// </summary>
public sealed class InvalidRefreshTokenError : ApiError
{
    public InvalidRefreshTokenError()
        : base(
            code: "INVALID_REFRESH_TOKEN",
            message: "Refresh token is invalid or expired",
            status: (int)HttpStatusCode.Unauthorized,
            details: null)
    {
    }

    public InvalidRefreshTokenError(string details)
        : base(
            code: "INVALID_REFRESH_TOKEN",
            message: "Refresh token is invalid or expired",
            status: (int)HttpStatusCode.Unauthorized,
            details: details)
    {
    }
}