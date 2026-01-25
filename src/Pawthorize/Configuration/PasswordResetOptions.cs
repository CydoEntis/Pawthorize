namespace Pawthorize.Configuration;

/// <summary>
/// Configuration options for password reset.
/// </summary>
public class PasswordResetOptions
{
    /// <summary>
    /// How long password reset tokens are valid.
    /// Default: 1 hour
    /// </summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Base URL for your application (used to build reset links).
    /// Example: "https://myapp.com"
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Path to append to BaseUrl for password reset endpoint.
    /// Default: "/reset-password"
    /// Full URL will be: {BaseUrl}{ResetPath}?token={token}
    /// </summary>
    public string ResetPath { get; set; } = "/reset-password";

    /// <summary>
    /// Application name to display in emails.
    /// Default: "Application Name"
    /// </summary>
    public string ApplicationName { get; set; } = "Application Name";
}
