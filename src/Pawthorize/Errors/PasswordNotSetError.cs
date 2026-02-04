using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when an operation requires a password but the user's account has none set (e.g. OAuth-only accounts).
/// Returns 400 Bad Request.
/// </summary>
public sealed class PasswordNotSetError : ApiError
{
    /// <summary>
    /// Creates a password not set error.
    /// </summary>
    public PasswordNotSetError()
        : base(
            code: "PASSWORD_NOT_SET",
            message: "Your account does not have a password set. Please set a password first.",
            status: (int)HttpStatusCode.BadRequest,
            details: new { action = "Use the set-password endpoint to set a password" })
    {
    }
}
