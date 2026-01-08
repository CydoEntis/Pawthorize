using System.Net;
using ErrorHound.Core;

namespace Pawthorize.Errors;

/// <summary>
/// Base class for OAuth-related errors.
/// </summary>
public abstract class OAuthError : ApiError
{
    protected OAuthError(string code, string message, int status = (int)HttpStatusCode.BadRequest, string? details = null)
        : base(code, message, status, details)
    {
    }
}
