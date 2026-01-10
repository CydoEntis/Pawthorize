using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.DTOs;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Services;
using Pawthorize.Utilities;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for user login (authentication).
/// Validates credentials, checks account status, and returns tokens.
/// </summary>
public class LoginHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly AuthenticationService<TUser> _authService;
    private readonly IValidator<LoginRequest> _validator;
    private readonly PawthorizeOptions _options;
    private readonly AccountLockoutOptions _lockoutOptions;
    private readonly CsrfTokenService _csrfService;
    private readonly ILogger<LoginHandler<TUser>> _logger;

    public LoginHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        AuthenticationService<TUser> authService,
        IValidator<LoginRequest> validator,
        IOptions<PawthorizeOptions> options,
        IOptions<AccountLockoutOptions> lockoutOptions,
        CsrfTokenService csrfService,
        ILogger<LoginHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _authService = authService;
        _validator = validator;
        _options = options.Value;
        _lockoutOptions = lockoutOptions.Value;
        _csrfService = csrfService;
        _logger = logger;
    }

    /// <summary>
    /// Handle login request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        LoginRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Login attempt initiated for email: {Email}", request.Email);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Login request validation passed for email: {Email}", request.Email);

            var user = await _userRepository.FindByEmailAsync(request.Email, cancellationToken);

            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found for email: {Email}", request.Email);
                throw new InvalidCredentialsError();
            }

            _logger.LogDebug("User found for email: {Email}, UserId: {UserId}", request.Email, user.Id);

            // Check if account is locked
            if (_lockoutOptions.Enabled && user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.UtcNow)
            {
                var remainingMinutes = (int)(user.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes + 1;
                _logger.LogWarning("Login failed: Account locked for email: {Email}, UserId: {UserId}, Lockout ends in {Minutes} minutes",
                    request.Email, user.Id, remainingMinutes);
                throw new AccountLockedError($"Account is locked. Please try again in {remainingMinutes} minute(s).");
            }

            if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid password for email: {Email}, UserId: {UserId}",
                    request.Email, user.Id);

                // Increment failed login attempts
                if (_lockoutOptions.Enabled)
                {
                    user.FailedLoginAttempts++;
                    _logger.LogDebug("Failed login attempts incremented to {Count} for UserId: {UserId}",
                        user.FailedLoginAttempts, user.Id);

                    // Lock account if max attempts exceeded
                    if (user.FailedLoginAttempts >= _lockoutOptions.MaxFailedAttempts)
                    {
                        user.LockoutEnd = DateTime.UtcNow.AddMinutes(_lockoutOptions.LockoutMinutes);
                        _logger.LogWarning("Account locked due to {Count} failed attempts for UserId: {UserId}, Lockout until: {LockoutEnd}",
                            user.FailedLoginAttempts, user.Id, user.LockoutEnd);
                    }

                    await _userRepository.UpdateAsync(user, cancellationToken);
                }

                throw new InvalidCredentialsError();
            }

            _logger.LogDebug("Password verification successful for UserId: {UserId}", user.Id);

            // Reset failed login attempts on successful login
            if (_lockoutOptions.Enabled && _lockoutOptions.ResetOnSuccessfulLogin && user.FailedLoginAttempts > 0)
            {
                _logger.LogDebug("Resetting failed login attempts from {Count} to 0 for UserId: {UserId}",
                    user.FailedLoginAttempts, user.Id);
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                await _userRepository.UpdateAsync(user, cancellationToken);
            }

            _authService.ValidateAccountStatus(user);
            _logger.LogDebug("Account status validation passed for UserId: {UserId}", user.Id);

            var authResult = await _authService.GenerateTokensAsync(user, cancellationToken);
            _logger.LogDebug("Tokens generated successfully for UserId: {UserId}", user.Id);

            var result = TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery, _options, _csrfService, _logger);

            _logger.LogInformation("Login successful for email: {Email}, UserId: {UserId}",
                request.Email, user.Id);

            return result;
        }
        catch (InvalidCredentialsError)
        {
            _logger.LogError("Login failed: Invalid credentials for email: {Email}", request.Email);
            throw;
        }
        catch (EmailNotVerifiedError ex)
        {
            _logger.LogWarning("Login failed: Email not verified for email: {Email}", request.Email);
            throw;
        }
        catch (AccountLockedError ex)
        {
            _logger.LogWarning("Login failed: Account locked for email: {Email}", request.Email);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for email: {Email}", request.Email);
            throw;
        }
    }
}