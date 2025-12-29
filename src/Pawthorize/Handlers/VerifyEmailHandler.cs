using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.DTOs;
using Pawthorize.Errors;
using Pawthorize.Utilities;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for email verification.
/// Validates the token and marks the user's email as verified.
/// </summary>
public class VerifyEmailHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IEmailVerificationService _emailVerificationService;
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IValidator<VerifyEmailRequest> _validator;
    private readonly ILogger<VerifyEmailHandler<TUser>> _logger;

    public VerifyEmailHandler(
        IEmailVerificationService emailVerificationService,
        IUserRepository<TUser> userRepository,
        IValidator<VerifyEmailRequest> validator,
        ILogger<VerifyEmailHandler<TUser>> logger)
    {
        _emailVerificationService = emailVerificationService;
        _userRepository = userRepository;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Handle email verification request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        VerifyEmailRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Email verification attempt with token");

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Email verification request validation passed");

            var userId = await _emailVerificationService.VerifyEmailAsync(request.Token, cancellationToken);

            if (userId == null)
            {
                _logger.LogWarning("Email verification failed: Invalid or expired token");
                throw new InvalidVerificationTokenError();
            }

            _logger.LogDebug("Email verification token validated for UserId: {UserId}", userId);

            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Email verification failed: User not found for UserId: {UserId}", userId);
                throw new UserNotFoundError();
            }

            // Check if user is a concrete class with a settable IsEmailVerified property
            if (user.GetType().GetProperty(nameof(IAuthenticatedUser.IsEmailVerified))?.SetMethod == null)
            {
                _logger.LogError("Email verification failed: User type {UserType} does not have a settable IsEmailVerified property",
                    user.GetType().Name);
                throw new InvalidOperationException(
                    $"User type '{user.GetType().Name}' must have a settable IsEmailVerified property to support email verification.");
            }

            // Mark email as verified
            user.GetType().GetProperty(nameof(IAuthenticatedUser.IsEmailVerified))!.SetValue(user, true);

            await _userRepository.UpdateAsync(user, cancellationToken);

            _logger.LogInformation("Email verified successfully for UserId: {UserId}, Email: {Email}",
                userId, user.Email);

            var result = new
            {
                message = "Email verified successfully. You can now log in.",
                email = user.Email
            };

            return result.Ok(httpContext);
        }
        catch (InvalidVerificationTokenError)
        {
            throw;
        }
        catch (UserNotFoundError)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during email verification");
            throw;
        }
    }
}
