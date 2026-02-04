using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.ChangeEmail;

/// <summary>
/// Handler for verifying email change via token.
/// Validates token, updates email, and redirects to frontend callback URL.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class VerifyEmailChangeHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IEmailChangeService _emailChangeService;
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly IOptions<PawthorizeOptions> _options;
    private readonly ILogger<VerifyEmailChangeHandler<TUser>> _logger;

    public VerifyEmailChangeHandler(
        IUserRepository<TUser> userRepository,
        IEmailChangeService emailChangeService,
        IEmailSender emailSender,
        IEmailTemplateProvider templateProvider,
        IOptions<PawthorizeOptions> options,
        ILogger<VerifyEmailChangeHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _emailChangeService = emailChangeService;
        _emailSender = emailSender;
        _templateProvider = templateProvider;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Validates the email-change token, applies the new email, and redirects to the frontend callback.
    /// Sends a security notification to the old email address if configured.
    /// </summary>
    /// <exception cref="InvalidOperationException">FrontendCallbackUrl is not configured.</exception>
    public async Task<IResult> HandleAsync(
        string token,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Email change verification attempt with token");

        try
        {
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Email change verification failed: Token is missing");
                return RedirectToCallback("error", "Token is required");
            }

            var tokenInfo = await _emailChangeService.VerifyEmailChangeAsync(token, cancellationToken);

            if (tokenInfo == null)
            {
                _logger.LogWarning("Email change verification failed: Invalid or expired token");
                return RedirectToCallback("error", "Invalid or expired token");
            }

            _logger.LogDebug("Email change token validated for UserId: {UserId}, NewEmail: {NewEmail}",
                tokenInfo.UserId, tokenInfo.NewEmail);

            var user = await _userRepository.FindByIdAsync(tokenInfo.UserId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Email change verification failed: User not found for UserId: {UserId}", tokenInfo.UserId);
                return RedirectToCallback("error", "User not found");
            }

            var oldEmail = user.Email;

            user.Email = tokenInfo.NewEmail;
            user.IsEmailVerified = true; // New email was just verified

            await _userRepository.UpdateAsync(user, cancellationToken);

            _logger.LogInformation(
                "Email changed from {OldEmail} to {NewEmail} for UserId: {UserId}",
                oldEmail, tokenInfo.NewEmail, user.Id);

            // Send security notification to old email if enabled
            var emailChangeOptions = _options.Value.EmailChange;
            if (emailChangeOptions.SendNotificationToOldEmail && !string.IsNullOrEmpty(oldEmail))
            {
                try
                {
                    var notificationBody = _templateProvider.GetEmailChangeNotificationTemplate(
                        oldEmail,
                        tokenInfo.NewEmail,
                        emailChangeOptions.ApplicationName);

                    await _emailSender.SendEmailAsync(
                        to: oldEmail,
                        subject: $"Your email address was changed - {emailChangeOptions.ApplicationName}",
                        htmlBody: notificationBody,
                        cancellationToken: cancellationToken);

                    _logger.LogInformation(
                        "Security notification sent to old email {OldEmail} for UserId: {UserId}",
                        oldEmail, user.Id);
                }
                catch (Exception ex)
                {
                    // Log but don't fail the request if notification fails
                    _logger.LogWarning(ex,
                        "Failed to send security notification to old email {OldEmail} for UserId: {UserId}",
                        oldEmail, user.Id);
                }
            }

            _logger.LogInformation("Email change verification completed successfully for UserId: {UserId}", user.Id);

            return RedirectToCallback("emailChanged", "true");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during email change verification");
            return RedirectToCallback("error", "An unexpected error occurred");
        }
    }

    /// <summary>
    /// Redirect to frontend callback URL with query parameters.
    /// </summary>
    private IResult RedirectToCallback(string key, string value)
    {
        var callbackUrl = _options.Value.EmailChange.FrontendCallbackUrl;

        if (string.IsNullOrEmpty(callbackUrl))
        {
            _logger.LogError("EmailChange.FrontendCallbackUrl is not configured");
            throw new InvalidOperationException(
                "EmailChange.FrontendCallbackUrl is not configured. Set 'Pawthorize:EmailChange:FrontendCallbackUrl' in appsettings.json");
        }

        var queryParams = new Dictionary<string, string?> { [key] = value };
        var redirectUrl = QueryHelpers.AddQueryString(callbackUrl, queryParams);

        return Results.Redirect(redirectUrl);
    }
}
