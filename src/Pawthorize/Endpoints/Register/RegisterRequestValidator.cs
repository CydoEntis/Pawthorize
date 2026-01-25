using FluentValidation;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.Register;

/// <summary>
/// Validator for registration requests.
/// Enforces password strength requirements using configured password policy.
/// </summary>
public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator(PasswordValidationService passwordValidationService)
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Email must be a valid email address")
            .MaximumLength(255)
            .WithMessage("Email must not exceed 255 characters");

        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required")
            .Custom((password, context) =>
            {
                var result = passwordValidationService.Validate(password);
                if (!result.IsValid)
                {
                    foreach (var error in result.Errors)
                    {
                        context.AddFailure("Password", error);
                    }
                }
            });

        RuleFor(x => x.Name)
            .MaximumLength(100)
            .WithMessage("Name must not exceed 100 characters")
            .When(x => !string.IsNullOrWhiteSpace(x.Name));
    }
}
