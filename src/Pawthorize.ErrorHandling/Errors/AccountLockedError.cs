using System.Net;
using ErrorHound.Core;

namespace Pawthorize.ErrorHandling.Errors;

/// <summary>
/// Error thrown when account is locked due to security reasons.
/// Returns 403 Forbidden.
/// </summary>
public sealed class AccountLockedError : ApiError
{
    public AccountLockedError()
        : base(
            code: "ACCOUNT_LOCKED",
            message: "Account is temporarily locked",
            status: (int)HttpStatusCode.Forbidden,
            details: null)
    {
    }

    /// <summary>
    /// Create error with unlock time
    /// </summary>
    public AccountLockedError(DateTime unlockAt)
        : base(
            code: "ACCOUNT_LOCKED",
            message: "Account is temporarily locked due to multiple failed login attempts",
            status: (int)HttpStatusCode.Forbidden,
            details: new
            {
                unlockAt,
                reason = "Too many failed login attempts",
                action = "Please wait before trying again"
            })
    {
    }

    /// <summary>
    /// Create error with custom reason
    /// </summary>
    public AccountLockedError(string reason, DateTime? unlockAt = null)
        : base(
            code: "ACCOUNT_LOCKED",
            message: "Account is locked",
            status: (int)HttpStatusCode.Forbidden,
            details: unlockAt.HasValue
                ? new { reason, unlockAt = unlockAt.Value }
                : new { reason })
    {
    }
}