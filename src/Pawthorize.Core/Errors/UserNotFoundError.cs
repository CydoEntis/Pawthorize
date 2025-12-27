using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Core.Errors;

/// <summary>
/// Error thrown when a user is not found.
/// Returns 404 Not Found.
/// For security: In forgot password flow, return success even if user doesn't exist
/// to prevent email enumeration attacks.
/// </summary>
public sealed class UserNotFoundError : ApiError
{
    /// <summary>
    /// Creates a generic user not found error.
    /// </summary>
    public UserNotFoundError()
        : base(
            code: "USER_NOT_FOUND",
            message: "User not found",
            status: (int)HttpStatusCode.NotFound,
            details: null)
    {
    }

    /// <summary>
    /// Create error with custom details
    /// </summary>
    public UserNotFoundError(string details)
        : base(
            code: "USER_NOT_FOUND",
            message: "User not found",
            status: (int)HttpStatusCode.NotFound,
            details: details)
    {
    }
}
