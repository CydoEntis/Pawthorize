using FluentValidation;
using Pawthorize.DTOs;

namespace Pawthorize.Validators;

/// <summary>
/// Validator for email verification requests.
/// </summary>
public class VerifyEmailRequestValidator : AbstractValidator<VerifyEmailRequest>
{
    public VerifyEmailRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty()
            .WithMessage("Verification token is required")
            .MinimumLength(32)
            .WithMessage("Invalid verification token format");
    }
}
