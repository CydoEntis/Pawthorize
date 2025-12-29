namespace Pawthorize.DTOs;

/// <summary>
/// Request model for verifying email with a verification token.
/// </summary>
public class VerifyEmailRequest
{
    /// <summary>
    /// Email verification token (from email link)
    /// </summary>
    public string Token { get; set; } = string.Empty;
}
