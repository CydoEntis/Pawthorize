using FluentValidation;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.SetPassword;

/// <summary>
/// Validator for set password requests.
/// Enforces password strength requirements using configured password policy.
/// </summary>
public class SetPasswordRequestValidator : AbstractValidator<SetPasswordRequest>
{
    public SetPasswordRequestValidator(PasswordValidationService passwordValidationService)
    {
        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .WithMessage("Password is required")
            .Custom((newPassword, context) =>
            {
                var result = passwordValidationService.Validate(newPassword);
                if (!result.IsValid)
                {
                    foreach (var error in result.Errors)
                    {
                        context.AddFailure("NewPassword", error);
                    }
                }
            });

        RuleFor(x => x.ConfirmPassword)
            .NotEmpty()
            .WithMessage("Password confirmation is required")
            .Equal(x => x.NewPassword)
            .WithMessage("Passwords do not match");
    }
}
