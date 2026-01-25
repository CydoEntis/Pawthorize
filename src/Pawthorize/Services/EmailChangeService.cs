using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Internal;

namespace Pawthorize.Services;

/// <summary>
/// Implementation of email change service.
/// Handles token generation, storage, and email sending for email changes.
/// </summary>
public class EmailChangeService : IEmailChangeService
{
    private readonly IEmailChangeTokenRepository _tokenRepository;
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly EmailChangeOptions _options;
    private readonly PawthorizeOptions _pawthorizeOptions;

    /// <summary>
    /// Initializes a new instance of the EmailChangeService.
    /// </summary>
    /// <param name="tokenRepository">Repository for storing email change tokens.</param>
    /// <param name="emailSender">Service for sending emails.</param>
    /// <param name="templateProvider">Provider for email templates.</param>
    /// <param name="options">Pawthorize configuration options.</param>
    public EmailChangeService(
        IEmailChangeTokenRepository tokenRepository,
        IEmailSender emailSender,
        IEmailTemplateProvider templateProvider,
        IOptions<PawthorizeOptions> options)
    {
        _tokenRepository = tokenRepository;
        _emailSender = emailSender;
        _templateProvider = templateProvider;
        _pawthorizeOptions = options.Value;
        _options = options.Value.EmailChange;
    }

    /// <summary>
    /// Initiate email change by sending verification email to new address.
    /// If RequireEmailVerification is false, this method should not be called directly.
    /// </summary>
    public async Task<bool> InitiateEmailChangeAsync(
        string userId,
        string currentEmail,
        string newEmail,
        CancellationToken cancellationToken = default)
    {
        // If email verification is not required, return false to indicate immediate update
        if (!_pawthorizeOptions.RequireEmailVerification)
        {
            return false;
        }

        // Invalidate any existing email change tokens for this user
        await _tokenRepository.InvalidateAllTokensForUserAsync(
            userId,
            TokenType.EmailChange,
            cancellationToken);

        var token = TokenGenerator.GenerateToken(32);
        var tokenHash = TokenHasher.HashToken(token);
        var expiresAt = DateTime.UtcNow.Add(_options.TokenLifetime);

        await _tokenRepository.StoreEmailChangeTokenAsync(
            userId,
            tokenHash,
            newEmail,
            expiresAt,
            cancellationToken);

        var verificationUrl = BuildVerificationUrl(token);

        var htmlBody = _templateProvider.GetEmailChangeVerificationTemplate(verificationUrl, newEmail, currentEmail);

        await _emailSender.SendEmailAsync(
            to: newEmail,
            subject: $"Verify your new email address for {_options.ApplicationName}",
            htmlBody: htmlBody,
            cancellationToken: cancellationToken);

        return true;
    }

    /// <summary>
    /// Verify an email change token and retrieve the new email.
    /// </summary>
    public async Task<EmailChangeTokenInfo?> VerifyEmailChangeAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var tokenHash = TokenHasher.HashToken(token);
        var tokenInfo = await _tokenRepository.ConsumeEmailChangeTokenAsync(
            tokenHash,
            cancellationToken);

        if (tokenInfo == null || tokenInfo.IsExpired)
        {
            return null;
        }

        return tokenInfo;
    }

    /// <summary>
    /// Build the full verification URL with token.
    /// </summary>
    private string BuildVerificationUrl(string token)
    {
        if (string.IsNullOrEmpty(_options.BaseUrl))
        {
            throw new InvalidOperationException(
                "EmailChange.BaseUrl is not configured. " +
                "Set 'Pawthorize:EmailChange:BaseUrl' in appsettings.json");
        }

        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var path = _options.VerificationPath.TrimStart('/');
        
        return $"{baseUrl}/{path}?token={token}";
    }
}
