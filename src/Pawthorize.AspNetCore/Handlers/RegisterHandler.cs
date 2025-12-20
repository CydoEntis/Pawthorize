using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Services;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

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

    public RegisterHandler(
        IUserRepository<TUser> userRepository,
        IUserFactory<TUser, TRegisterRequest> userFactory,
        IPasswordHasher passwordHasher,
        AuthenticationService<TUser> authService,
        IValidator<TRegisterRequest> validator,
        IOptions<PawthorizeOptions> options,
        IEmailVerificationService? emailVerificationService = null)
    {
        _userRepository = userRepository;
        _userFactory = userFactory;
        _passwordHasher = passwordHasher;
        _authService = authService;
        _emailVerificationService = emailVerificationService;
        _validator = validator;
        _options = options.Value;
    }

    /// <summary>
    /// Handle registration request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        TRegisterRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken);

        if (await _userRepository.EmailExistsAsync(request.Email, cancellationToken))
        {
            throw new DuplicateEmailError(request.Email);
        }

        var passwordHash = _passwordHasher.HashPassword(request.Password);

        var user = _userFactory.CreateUser(request, passwordHash);

        var createdUser = await _userRepository.CreateAsync(user, cancellationToken);

        if (_options.RequireEmailVerification)
        {
            return await HandleEmailVerificationRequiredAsync(createdUser, cancellationToken);
        }

        var authResult = await _authService.GenerateTokensAsync(createdUser, cancellationToken);
        return TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery);
    }

    /// <summary>
    /// Handle registration when email verification is required.
    /// Sends verification email and returns success message (no tokens).
    /// </summary>
    private async Task<IResult> HandleEmailVerificationRequiredAsync(
        TUser user,
        CancellationToken cancellationToken)
    {
        if (_emailVerificationService == null)
        {
            throw new InvalidOperationException(
                "Email verification is required but IEmailVerificationService is not registered. " +
                "Register IEmailVerificationService in your DI container.");
        }

        await _emailVerificationService.SendVerificationEmailAsync(
            user.Id,
            user.Email,
            cancellationToken);

        var response = new
        {
            Message = "Registration successful. Please check your email to verify your account.",
            Email = user.Email
        };

        return response.Ok();
    }
}
