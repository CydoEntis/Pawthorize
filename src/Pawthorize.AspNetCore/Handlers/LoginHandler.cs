using FluentValidation;
using Microsoft.AspNetCore.Http;
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

    public LoginHandler(
        IUserRepository<TUser> userRepository,
        IPasswordHasher passwordHasher,
        AuthenticationService<TUser> authService,
        IValidator<LoginRequest> validator,
        IOptions<PawthorizeOptions> options)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
        _authService = authService;
        _validator = validator;
        _options = options.Value;
    }

    /// <summary>
    /// Handle login request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        LoginRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken);

        var user = await _userRepository.FindByIdentifierAsync(request.Identifier, cancellationToken);

        if (user == null || !_passwordHasher.VerifyPassword(request.Password, user.PasswordHash))
        {
            throw new InvalidCredentialsError();
        }

        _authService.ValidateAccountStatus(user);

        var authResult = await _authService.GenerateTokensAsync(user, cancellationToken);

        return TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery);
    }
}