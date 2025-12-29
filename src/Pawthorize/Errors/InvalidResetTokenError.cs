using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when a password reset token is invalid or expired.
/// Returns 400 Bad Request.
/// </summary>
public sealed class InvalidResetTokenError : ApiError
{
    /// <summary>
    /// Creates a generic invalid reset token error.
    /// </summary>
    public InvalidResetTokenError()
        : base(
            code: "INVALID_RESET_TOKEN",
            message: "Password reset token is invalid or has expired",
            status: (int)HttpStatusCode.BadRequest,
            details: new { action = "Request a new password reset" })
    {
    }

    /// <summary>
    /// Create error with custom details
    /// </summary>
    public InvalidResetTokenError(string details)
        : base(
            code: "INVALID_RESET_TOKEN",
            message: "Password reset token is invalid or has expired",
            status: (int)HttpStatusCode.BadRequest,
            details: details)
    {
    }
}
