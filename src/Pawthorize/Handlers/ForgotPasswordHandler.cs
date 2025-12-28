using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for forgot password requests.
/// Sends password reset email if user exists.
/// Always returns success to prevent email enumeration attacks.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class ForgotPasswordHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordResetService _passwordResetService;
    private readonly IValidator<ForgotPasswordRequest> _validator;
    private readonly ILogger<ForgotPasswordHandler<TUser>> _logger;

    public ForgotPasswordHandler(
        IUserRepository<TUser> userRepository,
        IPasswordResetService passwordResetService,
        IValidator<ForgotPasswordRequest> validator,
        ILogger<ForgotPasswordHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordResetService = passwordResetService;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Handle forgot password request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        ForgotPasswordRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Forgot password request initiated for email: {Email}", request.Email);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Forgot password request validation passed for email: {Email}", request.Email);

            var user = await _userRepository.FindByEmailAsync(request.Email, cancellationToken);

            if (user != null)
            {
                _logger.LogDebug("User found for email: {Email}, UserId: {UserId}", request.Email, user.Id);

                await _passwordResetService.SendPasswordResetEmailAsync(
                    user.Id,
                    user.Email,
                    cancellationToken);

                _logger.LogInformation("Password reset email sent successfully to {Email}, UserId: {UserId}",
                    user.Email, user.Id);
            }
            else
            {
                _logger.LogWarning("Forgot password request for non-existent email: {Email}", request.Email);
            }

            var response = new
            {
                Message = "If an account with that email exists, a password reset link has been sent.",
                Email = request.Email
            };

            _logger.LogInformation("Forgot password request completed for email: {Email}", request.Email);

            return response.Ok(httpContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during forgot password request for email: {Email}", request.Email);
            throw;
        }
    }
}
