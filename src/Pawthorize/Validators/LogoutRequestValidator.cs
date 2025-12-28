using FluentValidation;
using Pawthorize.AspNetCore.DTOs;

namespace Pawthorize.AspNetCore.Validators;

/// <summary>
/// Validator for logout requests.
/// </summary>
public class LogoutRequestValidator : AbstractValidator<LogoutRequest>
{
    public LogoutRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty()
            .WithMessage("Refresh token is required")
            .MinimumLength(64)
            .WithMessage("Invalid refresh token format");
    }
}