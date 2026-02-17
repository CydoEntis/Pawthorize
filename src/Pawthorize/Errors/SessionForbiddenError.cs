using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when an authenticated user attempts to revoke a session that belongs to another user.
/// Returns 403 Forbidden.
/// </summary>
public sealed class SessionForbiddenError : ApiError
{
    /// <summary>
    /// Creates a session forbidden error.
    /// </summary>
    public SessionForbiddenError()
        : base(
            code: "SESSION_FORBIDDEN",
            message: "You do not have permission to revoke this session",
            status: (int)HttpStatusCode.Forbidden,
            details: null)
    {
    }
}
