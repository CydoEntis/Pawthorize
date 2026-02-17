using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when a request requires authentication but the user is not authenticated.
/// Returns 401 Unauthorized.
/// </summary>
public sealed class NotAuthenticatedError : ApiError
{
    /// <summary>
    /// Creates a not authenticated error.
    /// </summary>
    public NotAuthenticatedError()
        : base(
            code: "NOT_AUTHENTICATED",
            message: "Authentication required. Please log in",
            status: (int)HttpStatusCode.Unauthorized,
            details: null)
    {
    }
}
