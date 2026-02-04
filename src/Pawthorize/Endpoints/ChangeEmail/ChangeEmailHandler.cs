using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services;
using Pawthorize.Internal;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Endpoints.ChangeEmail;

/// <summary>
/// Handler for changing email address for authenticated users.
/// Requires password confirmation and optionally sends verification email to new address.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class ChangeEmailHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IEmailChangeService _emailChangeService;
    private readonly IEmailSender _emailSender;
    private readonly IEmailTemplateProvider _templateProvider;
    private readonly IValidator<ChangeEmailRequest> _validator;
    private readonly IOptions<PawthorizeOptions> _options;
    private readonly ILogger<ChangeEmailHandler<TUser>> _logger;

    public ChangeEmailHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        IEmailChangeService emailChangeService,
        IEmailSender emailSender,
        IEmailTemplateProvider templateProvider,
        IValidator<ChangeEmailRequest> validator,
        IOptions<PawthorizeOptions> options,
        ILogger<ChangeEmailHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _emailChangeService = emailChangeService;
        _emailSender = emailSender;
        _templateProvider = templateProvider;
        _validator = validator;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Validates the new email, optionally confirms the current password, and either updates
    /// immediately or sends a verification email depending on configuration.
    /// </summary>
    /// <exception cref="NotAuthenticatedError">User is not authenticated.</exception>
    /// <exception cref="UserNotFoundError">User record not found.</exception>
    /// <exception cref="SameEmailError">New email matches the current email.</exception>
    /// <exception cref="DuplicateEmailError">New email is already in use by another account.</exception>
    /// <exception cref="PasswordNotSetError">Password confirmation required but account has no password (OAuth-only).</exception>
    /// <exception cref="IncorrectPasswordError">Password confirmation did not match.</exception>
    public async Task<IResult> HandleAsync(
        ChangeEmailRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Change email request initiated");

        try
        {
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Change email failed: User not authenticated");
                throw new NotAuthenticatedError();
            }

            _logger.LogDebug("Change email request for UserId: {UserId}", userId);

            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Change email request validation passed for UserId: {UserId}", userId);

            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Change email failed: User not found for UserId: {UserId}", userId);
                throw new UserNotFoundError();
            }

            _logger.LogDebug("User found for UserId: {UserId}, Current Email: {Email}", user.Id, user.Email);

            if (string.Equals(user.Email, request.NewEmail, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Change email failed: New email same as current email for UserId: {UserId}", user.Id);
                throw new SameEmailError();
            }

            var existingUser = await _userRepository.FindByEmailAsync(request.NewEmail, cancellationToken);
            if (existingUser != null && existingUser.Id != userId)
            {
                _logger.LogWarning("Change email failed: Email already in use for UserId: {UserId}", user.Id);
                throw new DuplicateEmailError();
            }

            // Verify password if required
            if (_options.Value.EmailChange.RequirePasswordConfirmation)
            {
                if (string.IsNullOrEmpty(user.PasswordHash))
                {
                    _logger.LogWarning("Change email failed: User has no password set for UserId: {UserId}", user.Id);
                    throw new PasswordNotSetError();
                }

                if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
                {
                    _logger.LogWarning("Change email failed: Incorrect password for UserId: {UserId}", user.Id);
                    throw new IncorrectPasswordError();
                }

                _logger.LogDebug("Password verified successfully for UserId: {UserId}", user.Id);
            }

            var emailChangeOptions = _options.Value.EmailChange;

            // If email verification is required, send verification email
            if (_options.Value.RequireEmailVerification)
            {
                await _emailChangeService.InitiateEmailChangeAsync(
                    userId,
                    user.Email,
                    request.NewEmail,
                    cancellationToken);

                _logger.LogInformation(
                    "Email change verification email sent to {NewEmail} for UserId: {UserId}",
                    request.NewEmail, user.Id);

                var response = new
                {
                    message = "Verification email sent to new address. Please check your inbox."
                };

                return response.Ok(httpContext);
            }
            else
            {
                var oldEmail = user.Email;
                user.Email = request.NewEmail;
                user.IsEmailVerified = false; // New email not verified yet

                await _userRepository.UpdateAsync(user, cancellationToken);

                _logger.LogInformation(
                    "Email updated from {OldEmail} to {NewEmail} for UserId: {UserId}",
                    oldEmail, request.NewEmail, user.Id);

                // Send security notification to old email if enabled
                if (emailChangeOptions.SendNotificationToOldEmail && !string.IsNullOrEmpty(oldEmail))
                {
                    try
                    {
                        var notificationBody = _templateProvider.GetEmailChangeNotificationTemplate(
                            oldEmail,
                            request.NewEmail,
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

                var response = new
                {
                    message = "Email updated successfully."
                };

                return response.Ok(httpContext);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during change email");
            throw;
        }
    }
}
