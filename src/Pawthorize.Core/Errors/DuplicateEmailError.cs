using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Core.Errors;

/// <summary>
/// Error thrown when attempting to register with an email that already exists.
/// Returns 409 Conflict.
/// </summary>
public sealed class DuplicateEmailError : ApiError
{
    public DuplicateEmailError(string email)
        : base(
            code: "DUPLICATE_EMAIL",
            message: "An account with this email already exists",
            status: (int)HttpStatusCode.Conflict,
            details: new { email, action = "Try logging in or use password reset" })
    {
    }

    /// <summary>
    /// Generic version without revealing the email
    /// </summary>
    public DuplicateEmailError()
        : base(
            code: "DUPLICATE_EMAIL",
            message: "An account with this email already exists",
            status: (int)HttpStatusCode.Conflict,
            details: null)
    {
    }
}