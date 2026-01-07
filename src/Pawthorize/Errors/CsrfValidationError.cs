using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Error thrown when CSRF token validation fails.
/// Returns 403 Forbidden.
/// </summary>
public sealed class CsrfValidationError : ApiError
{
    /// <summary>
    /// Creates a CSRF validation error with specific reason and actionable hints.
    /// </summary>
    /// <param name="reason">The specific reason for validation failure (e.g., "Missing CSRF cookie").</param>
    /// <param name="cookieName">The name of the CSRF cookie being validated.</param>
    /// <param name="headerName">The name of the CSRF header being validated.</param>
    public CsrfValidationError(string reason, string cookieName, string headerName)
        : base(
            code: "CSRF_VALIDATION_FAILED",
            message: "CSRF token validation failed",
            status: (int)HttpStatusCode.Forbidden,
            details: new
            {
                reason,
                cookieName,
                headerName,
                hint = $"Read the CSRF token from the '{cookieName}' cookie and include it in the '{headerName}' request header. Both values must match.",
                example = $"{headerName}: <value-from-{cookieName}-cookie>",
                documentation = "CSRF tokens are automatically set in cookies after login/register. Your frontend must read the cookie value and include it in the header for state-changing requests (POST, PUT, DELETE, PATCH)."
            })
    {
    }

    /// <summary>
    /// Creates a generic CSRF validation error.
    /// </summary>
    public CsrfValidationError()
        : base(
            code: "CSRF_VALIDATION_FAILED",
            message: "CSRF token validation failed",
            status: (int)HttpStatusCode.Forbidden,
            details: "CSRF token is missing or does not match the expected value")
    {
    }
}
