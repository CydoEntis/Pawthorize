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
    
    /// <summary>
    /// Generate email change verification email HTML (sent to new address).
    /// </summary>
    /// <param name="verificationUrl">Full URL to verify email change (includes token)</param>
    /// <param name="newEmail">New email address</param>
    /// <param name="oldEmail">Current email address</param>
    /// <returns>HTML email body</returns>
    string GetEmailChangeVerificationTemplate(string verificationUrl, string newEmail, string oldEmail);
    
    /// <summary>
    /// Generate email change security notification email HTML (sent to old address).
    /// </summary>
    /// <param name="oldEmail">Old email address</param>
    /// <param name="newEmail">New email address</param>
    /// <param name="applicationName">Application name</param>
    /// <returns>HTML email body</returns>
    string GetEmailChangeNotificationTemplate(string oldEmail, string newEmail, string applicationName);
}