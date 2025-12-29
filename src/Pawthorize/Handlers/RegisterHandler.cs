using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.DTOs;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Services;
using Pawthorize.Utilities;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for user registration.
/// Creates new user account and optionally sends email verification.
/// Supports extended registration DTOs via generic TRegisterRequest.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
/// <typeparam name="TRegisterRequest">Registration request type (can be extended)</typeparam>
public class RegisterHandler<TUser, TRegisterRequest>
    where TUser : IAuthenticatedUser
    where TRegisterRequest : RegisterRequest
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IUserFactory<TUser, TRegisterRequest> _userFactory;
    private readonly IPasswordHasher _passwordHasher;
    private readonly AuthenticationService<TUser> _authService;
    private readonly IEmailVerificationService? _emailVerificationService;
    private readonly IValidator<TRegisterRequest> _validator;
    private readonly PawthorizeOptions _options;
    private readonly ILogger<RegisterHandler<TUser, TRegisterRequest>> _logger;

    public RegisterHandler(
        IUserRepository<TUser> userRepository,
        IUserFactory<TUser, TRegisterRequest> userFactory,
        IPasswordHasher passwordHasher,
        AuthenticationService<TUser> authService,
        IValidator<TRegisterRequest> validator,
        IOptions<PawthorizeOptions> options,
        ILogger<RegisterHandler<TUser, TRegisterRequest>> logger,
        IEmailVerificationService? emailVerificationService = null)
    {
        _userRepository = userRepository;
        _userFactory = userFactory;
        _passwordHasher = passwordHasher;
        _authService = authService;
        _emailVerificationService = emailVerificationService;
        _validator = validator;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Handle registration request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        TRegisterRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Registration attempt initiated for email: {Email}", request.Email);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Registration request validation passed for email: {Email}", request.Email);

            if (await _userRepository.EmailExistsAsync(request.Email, cancellationToken))
            {
                _logger.LogWarning("Registration failed: Duplicate email attempted: {Email}", request.Email);
                throw new DuplicateEmailError(request.Email);
            }

            _logger.LogDebug("Email uniqueness check passed for email: {Email}", request.Email);

            var passwordHash = _passwordHasher.HashPassword(request.Password);
            _logger.LogDebug("Password hashed successfully for email: {Email}", request.Email);

            var user = _userFactory.CreateUser(request, passwordHash);
            _logger.LogDebug("User entity created for email: {Email}", request.Email);

            var createdUser = await _userRepository.CreateAsync(user, cancellationToken);
            _logger.LogInformation("User created successfully with UserId: {UserId}, Email: {Email}",
                createdUser.Id, createdUser.Email);

            if (_options.RequireEmailVerification)
            {
                _logger.LogDebug("Email verification required, processing verification flow for UserId: {UserId}",
                    createdUser.Id);
                return await HandleEmailVerificationRequiredAsync(createdUser, httpContext, cancellationToken);
            }

            _logger.LogDebug("Email verification not required, generating tokens for UserId: {UserId}",
                createdUser.Id);

            var authResult = await _authService.GenerateTokensAsync(createdUser, cancellationToken);
            var result = TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery, _logger);

            _logger.LogInformation("Registration completed successfully for UserId: {UserId}, Email: {Email}",
                createdUser.Id, createdUser.Email);

            return result;
        }
        catch (DuplicateEmailError)
        {
            _logger.LogError("Registration failed: Duplicate email for {Email}", request.Email);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during registration for email: {Email}", request.Email);
            throw;
        }
    }

    /// <summary>
    /// Handle registration when email verification is required.
    /// Sends verification email and returns success message (no tokens).
    /// </summary>
    private async Task<IResult> HandleEmailVerificationRequiredAsync(
        TUser user,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (_emailVerificationService == null)
        {
            _logger.LogError("Email verification service not configured but RequireEmailVerification is enabled for UserId: {UserId}",
                user.Id);
            throw new InvalidOperationException(
                "Email verification is required but IEmailVerificationService is not registered. " +
                "Register IEmailVerificationService in your DI container.");
        }

        try
        {
            await _emailVerificationService.SendVerificationEmailAsync(
                user.Id,
                user.Email,
                cancellationToken);

            _logger.LogInformation("Email verification email sent successfully to {Email}, UserId: {UserId}",
                user.Email, user.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email verification email to {Email}, UserId: {UserId}",
                user.Email, user.Id);
            throw;
        }

        var response = new
        {
            Message = "Registration successful. Please check your email to verify your account.",
            Email = user.Email
        };

        return response.Ok(httpContext);
    }
}
