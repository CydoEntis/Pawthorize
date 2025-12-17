using System.Net;
using ErrorHound.Core;

namespace Pawthorize.ErrorHandling.Errors;

/// <summary>
/// Error thrown when login credentials are invalid.
/// Returns 401 Unauthorized.
/// </summary>
public sealed class InvalidCredentialsError : ApiError
{
    public InvalidCredentialsError()
        : base(
            code: "INVALID_CREDENTIALS",
            message: "Invalid email or password",
            status: (int)HttpStatusCode.Unauthorized,
            details: null)
    {
    }

    /// <summary>
    /// Create error with custom details
    /// </summary>
    public InvalidCredentialsError(string details)
        : base(
            code: "INVALID_CREDENTIALS",
            message: "Invalid email or password",
            status: (int)HttpStatusCode.Unauthorized,
            details: details)
    {
    }
}