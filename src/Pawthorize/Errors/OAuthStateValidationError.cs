using System.Net;

namespace Pawthorize.Errors;

/// <summary>
/// Thrown when OAuth state token validation fails (CSRF protection).
/// Returns 400 Bad Request.
/// </summary>
public sealed class OAuthStateValidationError : OAuthError
{
    public OAuthStateValidationError(string message = "Invalid or expired OAuth state token. Please try signing in again.")
        : base(
            code: "OAUTH_STATE_INVALID",
            message: message,
            status: (int)HttpStatusCode.BadRequest)
    {
    }
}
