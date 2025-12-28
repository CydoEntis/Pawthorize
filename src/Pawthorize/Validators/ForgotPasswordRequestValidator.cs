using FluentValidation;
using Pawthorize.AspNetCore.DTOs;

namespace Pawthorize.AspNetCore.Validators;

/// <summary>
/// Validator for forgot password requests.
/// </summary>
public class ForgotPasswordRequestValidator : AbstractValidator<ForgotPasswordRequest>
{
    public ForgotPasswordRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Invalid email format")
            .MaximumLength(255)
            .WithMessage("Email must not exceed 255 characters");
    }
}
