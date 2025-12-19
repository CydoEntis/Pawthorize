using ErrorHound.BuiltIn;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;
using Pawthorize.Jwt.Services;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for user login (authentication).
/// Validates credentials, checks account status, and returns tokens.
/// </summary>
public class LoginHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly JwtService<TUser> _jwtService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IValidator<LoginRequest> _validator;
    private readonly PawthorizeOptions _options;

    public LoginHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        JwtService<TUser> jwtService,
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<LoginRequest> validator,
        IOptions<PawthorizeOptions> options)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _options = options.Value;
    }

    public async Task<IResult> HandleAsync(
        LoginRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        await ValidateRequestAsync(request, cancellationToken);

        var user = await _userRepository.FindByIdentifierAsync(request.Identifier, cancellationToken);

        if (user == null || !_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
        {
            throw new InvalidCredentialsError();
        }

        CheckAccountStatus(user);

        var authResult = await GenerateTokensAsync(user, cancellationToken);

        return TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery);
    }

    /// <summary>
    /// Validate login request using FluentValidation.
    /// </summary>
    private async Task ValidateRequestAsync(LoginRequest request, CancellationToken cancellationToken)
    {
        var validationResult = await _validator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            var validationError = new ValidationError();
            foreach (var error in validationResult.Errors)
            {
                validationError.AddFieldError(error.PropertyName, error.ErrorMessage);
            }

            throw validationError;
        }
    }

    /// <summary>
    /// Check if account is locked or email is not verified.
    /// </summary>
    private void CheckAccountStatus(TUser user)
    {
        {
            if (user.LockedUntil == null)
            {
                // Locked indefinitely
                throw new AccountLockedError("Account locked indefinitely", null);
            }
            else if (user.LockedUntil > DateTime.UtcNow)
            {
                // Locked temporarily
                throw new AccountLockedError(user.LockedUntil.Value);  
            }
        }

        if (_options.RequireEmailVerification && !user.IsEmailVerified)
        {
            throw new EmailNotVerifiedError(user.Email);
        }
    }

    /// <summary>
    /// Generate access and refresh tokens.
    /// </summary>
    private async Task<AuthResult> GenerateTokensAsync(TUser user, CancellationToken cancellationToken)
    {
        var accessToken = _jwtService.GenerateAccessToken(user);
        var accessTokenExpiresAt = DateTime.UtcNow.Add(_options.Jwt.AccessTokenLifetime);

        var refreshToken = _jwtService.GenerateRefreshToken();
        var refreshTokenExpiresAt = DateTime.UtcNow.Add(_options.Jwt.RefreshTokenLifetime);

        await _refreshTokenRepository.StoreAsync(
            refreshToken,
            user.Id,
            refreshTokenExpiresAt,
            cancellationToken);

        return new AuthResult
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshTokenExpiresAt = refreshTokenExpiresAt,
            TokenType = "Bearer"
        };
    }
}