using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Models;
using Pawthorize.Utilities;

namespace Pawthorize.Services;

/// <summary>
/// Implementation of password reset service.
/// Handles token generation, storage, and email sending.
/// </summary>
public class PasswordResetService : IPasswordResetService
{
    private readonly ITokenRepository _tokenRepository;
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly PasswordResetOptions _options;

    /// <summary>
    /// Initializes a new instance of the PasswordResetService.
    /// </summary>
    /// <param name="tokenRepository">Repository for storing reset tokens.</param>
    /// <param name="emailSender">Service for sending emails.</param>
    /// <param name="templateProvider">Provider for email templates.</param>
    /// <param name="options">Pawthorize configuration options.</param>
    public PasswordResetService(
        ITokenRepository tokenRepository,
        IEmailSender emailSender,
        IEmailTemplateProvider templateProvider,
        IOptions<PawthorizeOptions> options)
    {
        _tokenRepository = tokenRepository;
        _emailSender = emailSender;
        _templateProvider = templateProvider;
        _options = options.Value.PasswordReset;
    }

    /// <summary>
    /// Sends a password reset email to the user.
    /// </summary>
    /// <param name="userId">The user's unique identifier.</param>
    /// <param name="email">The email address to send the reset link to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The password reset token.</returns>
    public async Task<string> SendPasswordResetEmailAsync(
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
            TokenType.PasswordReset,
            expiresAt,
            cancellationToken);

        var resetUrl = BuildResetUrl(token);

        var htmlBody = _templateProvider.GetPasswordResetTemplate(resetUrl, email);

        await _emailSender.SendEmailAsync(
            to: email,
            subject: $"Reset your password for {_options.ApplicationName}",
            htmlBody: htmlBody,
            cancellationToken: cancellationToken);

        return token;
    }

    /// <summary>
    /// Validates a password reset token.
    /// </summary>
    /// <param name="token">The reset token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user ID if token is valid, null otherwise.</returns>
    public async Task<string?> ValidateResetTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var tokenHash = TokenHasher.HashToken(token);
        var tokenInfo = await _tokenRepository.ValidateTokenAsync(
            tokenHash,
            TokenType.PasswordReset,
            cancellationToken);

        if (tokenInfo == null || tokenInfo.IsExpired)
        {
            return null;
        }

        return tokenInfo.UserId;
    }

    /// <summary>
    /// Invalidates a password reset token after it has been used.
    /// </summary>
    /// <param name="token">The reset token to invalidate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task InvalidateResetTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var tokenHash = TokenHasher.HashToken(token);
        await _tokenRepository.InvalidateTokenAsync(
            tokenHash,
            TokenType.PasswordReset,
            cancellationToken);
    }

    /// <summary>
    /// Build the full password reset URL with token.
    /// </summary>
    private string BuildResetUrl(string token)
    {
        if (string.IsNullOrEmpty(_options.BaseUrl))
        {
            throw new InvalidOperationException(
                "PasswordReset.BaseUrl is not configured. " +
                "Set 'Pawthorize:PasswordReset:BaseUrl' in appsettings.json");
        }

        var baseUrl = _options.BaseUrl.TrimEnd('/');
        var path = _options.ResetPath.TrimStart('/');

        return $"{baseUrl}/{path}?token={token}";
    }
}
