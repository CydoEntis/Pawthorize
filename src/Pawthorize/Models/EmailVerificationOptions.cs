namespace Pawthorize.Models;

/// <summary>
/// Configuration options for email verification.
/// </summary>
public class EmailVerificationOptions
{
    /// <summary>
    /// How long verification tokens are valid.
    /// Default: 24 hours
    /// </summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromHours(24);
    
    /// <summary>
    /// Base URL for your application (used to build verification links).
    /// Example: "https://myapp.com"
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;
    
    /// <summary>
    /// Path to append to BaseUrl for email verification endpoint.
    /// Default: "/verify-email"
    /// Full URL will be: {BaseUrl}{VerificationPath}?token={token}
    /// </summary>
    public string VerificationPath { get; set; } = "/verify-email";
    
    /// <summary>
    /// Application name to display in emails.
    /// Default: "Application Name"
    /// </summary>
    public string ApplicationName { get; set; } = "Application Name";
}