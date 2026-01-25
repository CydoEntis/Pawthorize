using Pawthorize.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class TestEmailTemplateProvider : IEmailTemplateProvider
{
    public string GetEmailVerificationTemplate(string verificationUrl, string email)
    {
        return $"<html><body>Verify your email: <a href='{verificationUrl}'>Click here</a></body></html>";
    }

    public string GetPasswordResetTemplate(string resetUrl, string email)
    {
        return $"<html><body>Reset your password: <a href='{resetUrl}'>Click here</a></body></html>";
    }

    public string GetEmailChangeVerificationTemplate(string verificationUrl, string newEmail, string oldEmail)
    {
        return $"<html><body>Verify your new email: <a href='{verificationUrl}'>Click here</a></body></html>";
    }

    public string GetEmailChangeNotificationTemplate(string oldEmail, string newEmail, string applicationName)
    {
        return $"<html><body>Your email has been changed from {oldEmail} to {newEmail}.</body></html>";
    }
}
