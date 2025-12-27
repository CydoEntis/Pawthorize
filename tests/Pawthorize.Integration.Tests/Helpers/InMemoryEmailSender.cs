using Pawthorize.Core.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryEmailSender : IEmailSender
{
    public List<SentEmail> SentEmails { get; } = new();

    public Task SendEmailAsync(
        string to,
        string subject,
        string htmlBody,
        CancellationToken cancellationToken = default)
    {
        SentEmails.Add(new SentEmail
        {
            To = to,
            Subject = subject,
            HtmlBody = htmlBody,
            SentAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public void Clear() => SentEmails.Clear();

    public class SentEmail
    {
        public string To { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        public string HtmlBody { get; set; } = string.Empty;
        public DateTime SentAt { get; set; }
    }
}
