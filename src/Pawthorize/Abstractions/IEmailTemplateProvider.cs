namespace Pawthorize.Abstractions;

/// <summary>
/// Provider for email templates.
/// Consumer implements this to customize email branding and content.
/// </summary>
public interface IEmailTemplateProvider
{
    /// <summary>
    /// Generate email verification email HTML.
    /// </summary>
    /// <param name="verificationUrl">Full URL to verify email (includes token)</param>
    /// <param name="userEmail">User's email address</param>
    /// <returns>HTML email body</returns>
    string GetEmailVerificationTemplate(string verificationUrl, string userEmail);
    
    /// <summary>
    /// Generate password reset email HTML.
    /// </summary>
    /// <param name="resetUrl">Full URL to reset password (includes token)</param>
    /// <param name="userEmail">User's email address</param>
    /// <returns>HTML email body</returns>
    string GetPasswordResetTemplate(string resetUrl, string userEmail);
}