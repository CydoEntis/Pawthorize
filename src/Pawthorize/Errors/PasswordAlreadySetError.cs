using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when attempting to set a password for a user who already has one.
/// Returns 400 Bad Request.
/// </summary>
public sealed class PasswordAlreadySetError : ApiError
{
    /// <summary>
    /// Creates a password already set error.
    /// </summary>
    public PasswordAlreadySetError()
        : base(
            code: "PASSWORD_ALREADY_SET",
            message: "Password is already set. Use change-password endpoint instead.",
            status: (int)HttpStatusCode.BadRequest,
            details: null)
    {
    }
}
