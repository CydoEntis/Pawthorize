namespace Pawthorize.Configuration;

/// <summary>
/// Configuration options for account lockout protection.
/// Protects individual user accounts from brute force attacks by temporarily locking
/// accounts after repeated failed login attempts.
/// </summary>
public class AccountLockoutOptions
{
    /// <summary>
    /// Enable or disable account lockout.
    /// When enabled, accounts will be temporarily locked after exceeding max failed login attempts.
    /// Default: true (enabled for security)
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum number of failed login attempts before account is locked.
    /// Default: 5 attempts
    /// </summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>
    /// Duration in minutes that an account remains locked after exceeding max failed attempts.
    /// After this period, the account is automatically unlocked and failed attempt counter is reset.
    /// Default: 30 minutes
    /// </summary>
    public int LockoutMinutes { get; set; } = 30;

    /// <summary>
    /// Whether to reset the failed attempts counter on successful login.
    /// Default: true (recommended)
    /// </summary>
    public bool ResetOnSuccessfulLogin { get; set; } = true;
}
