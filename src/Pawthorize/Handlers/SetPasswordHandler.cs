using System.Security.Claims;
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
/// Handler for setting a password for OAuth-only users who don't have a password yet.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class SetPasswordHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IValidator<SetPasswordRequest> _validator;
    private readonly ILogger<SetPasswordHandler<TUser>> _logger;

    public SetPasswordHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        IValidator<SetPasswordRequest> validator,
        ILogger<SetPasswordHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Handle set password request for OAuth-only users.
    /// </summary>
    public async Task<IResult> HandleAsync(
        SetPasswordRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Set password request initiated");

        try
        {
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Set password failed: User not authenticated");
                throw new InvalidCredentialsError("User not authenticated");
            }

            _logger.LogDebug("Set password request for UserId: {UserId}", userId);

            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Set password request validation passed for UserId: {UserId}", userId);

            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Set password failed: User not found for UserId: {UserId}", userId);
                throw new UserNotFoundError();
            }

            _logger.LogDebug("User found for UserId: {UserId}, Email: {Email}", user.Id, user.Email);

            // Check if user already has a password
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                _logger.LogWarning("Set password failed: User already has a password for UserId: {UserId}", user.Id);
                throw new PasswordAlreadySetError();
            }

            _logger.LogDebug("Confirmed user has no password set for UserId: {UserId}", user.Id);

            var passwordHash = _passwordHasher.HashPassword(request.NewPassword);
            _logger.LogDebug("Password hashed successfully for UserId: {UserId}", user.Id);

            await _userRepository.UpdatePasswordAsync(userId, passwordHash, cancellationToken);
            _logger.LogInformation("Password set successfully for UserId: {UserId}", user.Id);

            var response = new
            {
                Message = "Password set successfully. You can now log in with email and password."
            };

            _logger.LogInformation("Set password completed successfully for UserId: {UserId}", user.Id);

            return response.Ok(httpContext);
        }
        catch (PasswordAlreadySetError)
        {
            _logger.LogError("Set password failed: User already has a password");
            throw;
        }
        catch (UserNotFoundError)
        {
            _logger.LogError("Set password failed: User not found");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during set password");
            throw;
        }
    }
}
