using System.Net;

namespace Pawthorize.Errors;

/// <summary>
/// Thrown when OAuth configuration is invalid.
/// Returns 500 Internal Server Error.
/// </summary>
public sealed class OAuthConfigurationError : OAuthError
{
    public OAuthConfigurationError(string message, string? details = null)
        : base(
            code: "OAUTH_CONFIG_ERROR",
            message: message,
            status: (int)HttpStatusCode.InternalServerError,
            details: details)
    {
    }
}
