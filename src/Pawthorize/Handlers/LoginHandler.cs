using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Services;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;

namespace Pawthorize.AspNetCore.Handlers;

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
    private readonly ILogger<LoginHandler<TUser>> _logger;

    public LoginHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        AuthenticationService<TUser> authService,
        IValidator<LoginRequest> validator,
        IOptions<PawthorizeOptions> options,
        ILogger<LoginHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _authService = authService;
        _validator = validator;
        _options = options.Value;
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
        _logger.LogInformation("Login attempt initiated for identifier: {Identifier}", request.Identifier);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Login request validation passed for identifier: {Identifier}", request.Identifier);

            var user = await _userRepository.FindByIdentifierAsync(request.Identifier, cancellationToken);

            if (user == null)
            {
                _logger.LogWarning("Login failed: User not found for identifier: {Identifier}", request.Identifier);
                throw new InvalidCredentialsError();
            }

            _logger.LogDebug("User found for identifier: {Identifier}, UserId: {UserId}", request.Identifier, user.Id);

            if (!_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning("Login failed: Invalid password for identifier: {Identifier}, UserId: {UserId}",
                    request.Identifier, user.Id);
                throw new InvalidCredentialsError();
            }

            _logger.LogDebug("Password verification successful for UserId: {UserId}", user.Id);

            _authService.ValidateAccountStatus(user);
            _logger.LogDebug("Account status validation passed for UserId: {UserId}", user.Id);

            var authResult = await _authService.GenerateTokensAsync(user, cancellationToken);
            _logger.LogDebug("Tokens generated successfully for UserId: {UserId}", user.Id);

            var result = TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery, _logger);

            _logger.LogInformation("Login successful for identifier: {Identifier}, UserId: {UserId}",
                request.Identifier, user.Id);

            return result;
        }
        catch (InvalidCredentialsError)
        {
            _logger.LogError("Login failed: Invalid credentials for identifier: {Identifier}", request.Identifier);
            throw;
        }
        catch (EmailNotVerifiedError ex)
        {
            _logger.LogWarning("Login failed: Email not verified for identifier: {Identifier}", request.Identifier);
            throw;
        }
        catch (AccountLockedError ex)
        {
            _logger.LogWarning("Login failed: Account locked for identifier: {Identifier}", request.Identifier);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for identifier: {Identifier}", request.Identifier);
            throw;
        }
    }
}