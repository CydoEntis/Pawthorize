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
}
