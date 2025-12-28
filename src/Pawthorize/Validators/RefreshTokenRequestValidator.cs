using FluentValidation;
using Pawthorize.AspNetCore.DTOs;

namespace Pawthorize.AspNetCore.Validators;

/// <summary>
/// Validator for refresh token requests.
/// </summary>
public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
{
    public RefreshTokenRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .MinimumLength(64)
            .When(x => !string.IsNullOrEmpty(x.RefreshToken))
            .WithMessage("Invalid refresh token format");
    }
}