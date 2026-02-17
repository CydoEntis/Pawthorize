using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when a session (refresh token) is not found or has already been revoked.
/// Returns 404 Not Found.
/// </summary>
public sealed class SessionNotFoundError : ApiError
{
    /// <summary>
    /// Creates a session not found error.
    /// </summary>
    public SessionNotFoundError()
        : base(
            code: "SESSION_NOT_FOUND",
            message: "Session not found or has already been revoked",
            status: (int)HttpStatusCode.NotFound,
            details: null)
    {
    }
}
