using Microsoft.Extensions.Options;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;
using Pawthorize.Security.Utilities;

namespace Pawthorize.Core.Services;

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

    public async Task<string> SendVerificationEmailAsync(
        string userId, 
        string email, 
        CancellationToken cancellationToken = default)
    {
        var token = TokenGenerator.GenerateToken(32);
        var expiresAt = DateTime.UtcNow.Add(_options.TokenLifetime);

        await _tokenRepository.StoreTokenAsync(
            userId, 
            token, 
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

    public async Task<string?> VerifyEmailAsync(
        string token, 
        CancellationToken cancellationToken = default)
    {
        var tokenInfo = await _tokenRepository.ValidateTokenAsync(
            token, 
            TokenType.EmailVerification, 
            cancellationToken);

        if (tokenInfo == null || tokenInfo.IsExpired)
        {
            return null;  
        }

        await _tokenRepository.InvalidateTokenAsync(
            token, 
            TokenType.EmailVerification, 
            cancellationToken);

        return tokenInfo.UserId;
    }

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