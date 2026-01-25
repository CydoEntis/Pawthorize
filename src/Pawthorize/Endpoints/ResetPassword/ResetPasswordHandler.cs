using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Services;
using Pawthorize.Internal;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Endpoints.ResetPassword;

/// <summary>
/// Handler for resetting password with a reset token.
/// Validates token, updates password, and invalidates the token.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class ResetPasswordHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordResetService _passwordResetService;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IValidator<ResetPasswordRequest> _validator;
    private readonly ILogger<ResetPasswordHandler<TUser>> _logger;

    public ResetPasswordHandler(
        IUserRepository<TUser> userRepository,
        IPasswordResetService passwordResetService,
        IPasswordHasher passwordHasher,
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<ResetPasswordRequest> validator,
        ILogger<ResetPasswordHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordResetService = passwordResetService;
        _passwordHasher = passwordHasher;
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Handle reset password request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        ResetPasswordRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Reset password request initiated");

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Reset password request validation passed");

            var userId = await _passwordResetService.ValidateResetTokenAsync(request.Token, cancellationToken);

            if (userId == null)
            {
                _logger.LogWarning("Reset password failed: Invalid or expired token");
                throw new InvalidResetTokenError();
            }

            _logger.LogDebug("Reset token validated successfully for UserId: {UserId}", userId);

            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Reset password failed: User not found for UserId: {UserId}", userId);
                throw new UserNotFoundError();
            }

            _logger.LogDebug("User found for UserId: {UserId}, Email: {Email}", user.Id, user.Email);

            var newPasswordHash = _passwordHasher.HashPassword(request.NewPassword);
            _logger.LogDebug("New password hashed successfully for UserId: {UserId}", user.Id);

            await _userRepository.UpdatePasswordAsync(userId, newPasswordHash, cancellationToken);
            _logger.LogInformation("Password updated successfully for UserId: {UserId}", user.Id);

            await _passwordResetService.InvalidateResetTokenAsync(request.Token, cancellationToken);
            _logger.LogDebug("Reset token invalidated for UserId: {UserId}", user.Id);

            await _refreshTokenRepository.RevokeAllForUserAsync(userId, cancellationToken);
            _logger.LogInformation("All refresh tokens revoked for UserId: {UserId}", user.Id);

            var response = new
            {
                Message = "Password reset successfully. Please log in with your new password."
            };

            _logger.LogInformation("Reset password completed successfully for UserId: {UserId}", user.Id);

            return response.Ok(httpContext);
        }
        catch (InvalidResetTokenError)
        {
            _logger.LogError("Reset password failed: Invalid reset token");
            throw;
        }
        catch (UserNotFoundError)
        {
            _logger.LogError("Reset password failed: User not found");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during reset password");
            throw;
        }
    }
}
