using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when user tries to login but email is not verified.
/// Returns 403 Forbidden.
/// </summary>
public sealed class EmailNotVerifiedError : ApiError
{
    /// <summary>
    /// Creates a generic email not verified error.
    /// </summary>
    public EmailNotVerifiedError()
        : base(
            code: "EMAIL_NOT_VERIFIED",
            message: "Please verify your email address before logging in",
            status: (int)HttpStatusCode.Forbidden,
            details: null)
    {
    }

    /// <summary>
    /// Creates an email not verified error with the email address.
    /// </summary>
    /// <param name="email">The unverified email address.</param>
    public EmailNotVerifiedError(string email)
        : base(
            code: "EMAIL_NOT_VERIFIED",
            message: "Please verify your email address before logging in",
            status: (int)HttpStatusCode.Forbidden,
            details: new { email, action = "Check your inbox for verification link" })
    {
    }
}