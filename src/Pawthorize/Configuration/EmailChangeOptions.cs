namespace Pawthorize.Configuration;

/// <summary>
/// Configuration options for email change.
/// </summary>
public class EmailChangeOptions
{
    /// <summary>
    /// Enable or disable email change functionality.
    /// Default: true
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// How long email change tokens are valid.
    /// Default: 1 hour
    /// </summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Base URL for your application (used to build verification links).
    /// Example: "https://myapp.com"
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Path to append to BaseUrl for email change verification endpoint.
    /// Default: "/verify-email-change"
    /// Full URL will be: {BaseUrl}{VerificationPath}?token={token}
    /// </summary>
    public string VerificationPath { get; set; } = "/verify-email-change";

    /// <summary>
    /// Frontend callback URL for redirects after email change verification.
    /// Example: "https://myapp.com/auth/callback"
    /// </summary>
    public string FrontendCallbackUrl { get; set; } = string.Empty;

    /// <summary>
    /// Application name to display in emails.
    /// Default: "Application Name"
    /// </summary>
    public string ApplicationName { get; set; } = "Application Name";

    /// <summary>
    /// Whether to require password confirmation when changing email.
    /// Default: true
    /// </summary>
    public bool RequirePasswordConfirmation { get; set; } = true;

    /// <summary>
    /// Whether to send a security notification to the old email when email is changed.
    /// Default: true
    /// </summary>
    public bool SendNotificationToOldEmail { get; set; } = true;
}
