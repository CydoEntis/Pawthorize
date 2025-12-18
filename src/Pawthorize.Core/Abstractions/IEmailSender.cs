namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Interface for sending emails.
/// Consumer implements this with their preferred email provider
/// (SendGrid, AWS SES, MailKit, SMTP, etc.)
/// </summary>
public interface IEmailSender
{
    /// <summary>
    /// Send an email.
    /// </summary>
    /// <param name="to">Recipient email address</param>
    /// <param name="subject">Email subject</param>
    /// <param name="htmlBody">Email body (HTML format)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task SendEmailAsync(
        string to,
        string subject,
        string htmlBody,
        CancellationToken cancellationToken = default);
}