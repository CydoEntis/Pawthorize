using Pawthorize.Core.Abstractions;

namespace Pawthorize.Sample.MinimalApi.Services;

public class InMemoryEmailSender : IEmailSender
{
    private readonly ILogger<InMemoryEmailSender> _logger;

    public InMemoryEmailSender(ILogger<InMemoryEmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendEmailAsync(
        string to,
        string subject,
        string htmlBody,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation(
            "📧 EMAIL SENT (In-Memory)\n" +
            "To: {To}\n" +
            "Subject: {Subject}\n" +
            "Body:\n{Body}\n" +
            "================================",
            to,
            subject,
            htmlBody);

        return Task.CompletedTask;
    }
}
