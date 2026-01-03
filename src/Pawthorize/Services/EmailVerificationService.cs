using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Models;
using Pawthorize.Utilities;

namespace Pawthorize.Services;

/// <summary>
/// Implementation of email verification service.
/// Handles token generation, storage, and email sending.
/// </summary>
public class EmailVerificationService : IEmailVerificationService
{
    private readonly ITokenRepository _tokenRepository;
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly EmailVerificationOptions _options;

    /// <summary>
    /// Initializes a new instance of the EmailVerificationService.
    /// </summary>
    /// <param name="tokenRepository">Repository for storing verification tokens.</param>
    /// <param name="emailSender">Service for sending emails.</param>
    /// <param name="templateProvider">Provider for email templates.</param>
    /// <param name="options">Pawthorize configuration options.</param>
    public EmailVerificationService(
        ITokenRepository tokenRepository,
        IEmailSender emailSender,
        IEmailTemplateProvider templateProvider,
        IOptions<PawthorizeOptions> options)
    {
        _tokenRepository = tokenRepository;
        _emailSender = emailSender;
        _templateProvider = templateProvider;
        _options = options.Value.EmailVerification;
    }

    /// <summary>
    /// Sends a verification email to the user.
    /// </summary>
    /// <param name="userId">The user's unique identifier.</param>
    /// <param name="email">The email address to send verification to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification token.</returns>
    public async Task<string> SendVerificationEmailAsync(
        string userId,
        string email,
        CancellationToken cancellationToken = default)
    {
        var token = TokenGenerator.GenerateToken(32);
        var tokenHash = TokenHasher.HashToken(token);
        var expiresAt = DateTime.UtcNow.Add(_options.TokenLifetime);

        await _tokenRepository.StoreTokenAsync(
            userId,
            tokenHash,
            TokenType.EmailVerification,
            expiresAt,
            cancellationToken);

        var verificationUrl = BuildVerificationUrl(token);

        var htmlBody = _templateProvider.GetEmailVerificationTemplate(verificationUrl, email);

        await _emailSender.SendEmailAsync(
            to: email,
            subject: $"Verify your email for {_options.ApplicationName}",
            htmlBody: htmlBody,
            cancellationToken: cancellationToken);

        return token;
    }

    /// <summary>
    /// Verifies an email using the provided token.
    /// </summary>
    /// <param name="token">The verification token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user ID if verification succeeds, null otherwise.</returns>
    public async Task<string?> VerifyEmailAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var tokenHash = TokenHasher.HashToken(token);
        var tokenInfo = await _tokenRepository.ConsumeTokenAsync(
            tokenHash,
            TokenType.EmailVerification,
            cancellationToken);

        if (tokenInfo == null || tokenInfo.IsExpired)
        {
            return null;
        }

        return tokenInfo.UserId;
    }

    /// <summary>
    /// Resends a verification email by invalidating old tokens and generating a new one.
    /// </summary>
    /// <param name="userId">The user's unique identifier.</param>
    /// <param name="email">The email address to send verification to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task ResendVerificationEmailAsync(
        string userId,
        string email,
        CancellationToken cancellationToken = default)
    {
        await _tokenRepository.InvalidateAllTokensForUserAsync(
            userId, 
            TokenType.EmailVerification, 
            cancellationToken);

        await SendVerificationEmailAsync(userId, email, cancellationToken);
    }

    /// <summary>
    /// Build the full verification URL with token.
    /// </summary>
    private string BuildVerificationUrl(string token)
    {
        if (string.IsNullOrEmpty(_options.BaseUrl))
        {
            throw new InvalidOperationException(
                "EmailVerification.BaseUrl is not configured. " +
                "Set 'Pawthorize:EmailVerification:BaseUrl' in appsettings.json");
        }

        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var path = _options.VerificationPath.TrimStart('/');
        
        return $"{baseUrl}/{path}?token={token}";
    }
}