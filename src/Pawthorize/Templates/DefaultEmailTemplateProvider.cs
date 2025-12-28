using System.Reflection;
using Pawthorize.Core.Abstractions;

namespace Pawthorize.Core.Templates;

/// <summary>
/// Default email template provider using embedded HTML templates.
/// Provides basic templates with simple variable substitution.
/// Replace with your own branded templates for production.
/// </summary>
public class DefaultEmailTemplateProvider : IEmailTemplateProvider
{
    private readonly string _appName;
    private static readonly Assembly _assembly = typeof(DefaultEmailTemplateProvider).Assembly;

    /// <summary>
    /// Initializes a new instance of the DefaultEmailTemplateProvider.
    /// </summary>
    /// <param name="appName">The application name to use in email templates.</param>
    public DefaultEmailTemplateProvider(string appName = "Our Application")
    {
        _appName = appName;
    }

    /// <summary>
    /// Gets the email verification template with populated variables.
    /// </summary>
    /// <param name="verificationUrl">The verification URL to include in the email.</param>
    /// <param name="userEmail">The user's email address.</param>
    /// <returns>HTML email body.</returns>
    public string GetEmailVerificationTemplate(string verificationUrl, string userEmail)
    {
        var template = LoadEmbeddedTemplate("EmailVerification.html");

        return template
            .Replace("{{AppName}}", _appName)
            .Replace("{{VerificationUrl}}", verificationUrl)
            .Replace("{{UserEmail}}", userEmail);
    }

    /// <summary>
    /// Gets the password reset template with populated variables.
    /// </summary>
    /// <param name="resetUrl">The password reset URL to include in the email.</param>
    /// <param name="userEmail">The user's email address.</param>
    /// <returns>HTML email body.</returns>
    public string GetPasswordResetTemplate(string resetUrl, string userEmail)
    {
        var template = LoadEmbeddedTemplate("PasswordReset.html");

        return template
            .Replace("{{AppName}}", _appName)
            .Replace("{{ResetUrl}}", resetUrl)
            .Replace("{{UserEmail}}", userEmail);
    }

    /// <summary>
    /// Load an embedded HTML template from the assembly.
    /// </summary>
    private static string LoadEmbeddedTemplate(string fileName)
    {
        var resourceName = $"Pawthorize.Core.Templates.EmailTemplates.{fileName}";

        using var stream = _assembly.GetManifestResourceStream(resourceName);

        if (stream == null)
        {
            throw new FileNotFoundException(
                $"Embedded template '{fileName}' not found. " +
                $"Make sure the file is marked as an EmbeddedResource in the .csproj file.");
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}