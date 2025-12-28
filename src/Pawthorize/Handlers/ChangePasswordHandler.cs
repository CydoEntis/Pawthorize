using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for changing password for authenticated users.
/// Requires current password verification before allowing change.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class ChangePasswordHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IValidator<ChangePasswordRequest> _validator;
    private readonly ILogger<ChangePasswordHandler<TUser>> _logger;

    public ChangePasswordHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<ChangePasswordRequest> validator,
        ILogger<ChangePasswordHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Handle change password request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        ChangePasswordRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Change password request initiated");

        try
        {
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Change password failed: User not authenticated");
                throw new InvalidCredentialsError("User not authenticated");
            }

            _logger.LogDebug("Change password request for UserId: {UserId}", userId);

            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Change password request validation passed for UserId: {UserId}", userId);

            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Change password failed: User not found for UserId: {UserId}", userId);
                throw new UserNotFoundError();
            }

            _logger.LogDebug("User found for UserId: {UserId}, Email: {Email}", user.Id, user.Email);

            if (!_passwordHasher.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            {
                _logger.LogWarning("Change password failed: Incorrect current password for UserId: {UserId}", user.Id);
                throw new IncorrectPasswordError();
            }

            _logger.LogDebug("Current password verified successfully for UserId: {UserId}", user.Id);

            var newPasswordHash = _passwordHasher.HashPassword(request.NewPassword);
            _logger.LogDebug("New password hashed successfully for UserId: {UserId}", user.Id);

            await _userRepository.UpdatePasswordAsync(userId, newPasswordHash, cancellationToken);
            _logger.LogInformation("Password updated successfully for UserId: {UserId}", user.Id);

            await _refreshTokenRepository.RevokeAllForUserAsync(userId, cancellationToken);
            _logger.LogInformation("All refresh tokens revoked for UserId: {UserId}", user.Id);

            var response = new
            {
                Message = "Password changed successfully. Please log in again with your new password."
            };

            _logger.LogInformation("Change password completed successfully for UserId: {UserId}", user.Id);

            return response.Ok(httpContext);
        }
        catch (IncorrectPasswordError)
        {
            _logger.LogError("Change password failed: Incorrect password");
            throw;
        }
        catch (UserNotFoundError)
        {
            _logger.LogError("Change password failed: User not found");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during change password");
            throw;
        }
    }
}
