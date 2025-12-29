using FluentValidation;
using Pawthorize.DTOs;

namespace Pawthorize.Validators;

/// <summary>
/// Validator for refresh token requests.
/// </summary>
public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
{
    public RefreshTokenRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty()
            .WithMessage("Refresh token is required")
            .MinimumLength(64)
            .WithMessage("Invalid refresh token format");
    }
}