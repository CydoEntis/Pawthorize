using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Core.Errors;

/// <summary>
/// Error thrown when the current password is incorrect (used in change password flow).
/// Returns 401 Unauthorized.
/// </summary>
public sealed class IncorrectPasswordError : ApiError
{
    /// <summary>
    /// Creates a generic incorrect password error.
    /// </summary>
    public IncorrectPasswordError()
        : base(
            code: "INCORRECT_PASSWORD",
            message: "Current password is incorrect",
            status: (int)HttpStatusCode.Unauthorized,
            details: null)
    {
    }

    /// <summary>
    /// Create error with custom details
    /// </summary>
    public IncorrectPasswordError(string details)
        : base(
            code: "INCORRECT_PASSWORD",
            message: "Current password is incorrect",
            status: (int)HttpStatusCode.Unauthorized,
            details: details)
    {
    }
}
