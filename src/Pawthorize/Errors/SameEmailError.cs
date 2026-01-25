using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when attempting to change email to the same email address.
/// Returns 400 Bad Request.
/// </summary>
public sealed class SameEmailError : ApiError
{
    /// <summary>
    /// Creates a same email error.
    /// </summary>
    public SameEmailError()
        : base(
            code: "SAME_EMAIL",
            message: "New email must be different from current email",
            status: (int)HttpStatusCode.BadRequest,
            details: null)
    {
    }
}
