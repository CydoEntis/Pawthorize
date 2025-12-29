using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when an email verification token is invalid or expired.
/// Returns 400 Bad Request.
/// </summary>
public sealed class InvalidVerificationTokenError : ApiError
{
    /// <summary>
    /// Creates a generic invalid verification token error.
    /// </summary>
    public InvalidVerificationTokenError()
        : base(
            code: "INVALID_VERIFICATION_TOKEN",
            message: "Email verification token is invalid or has expired",
            status: (int)HttpStatusCode.BadRequest,
            details: new { action = "Request a new verification email" })
    {
    }

    /// <summary>
    /// Create error with custom details
    /// </summary>
    public InvalidVerificationTokenError(string details)
        : base(
            code: "INVALID_VERIFICATION_TOKEN",
            message: "Email verification token is invalid or has expired",
            status: (int)HttpStatusCode.BadRequest,
            details: details)
    {
    }
}
