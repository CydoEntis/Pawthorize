using FluentValidation;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.ChangePassword;

/// <summary>
/// Validator for change password requests.
/// Enforces password strength requirements using configured password policy.
/// </summary>
public class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator(PasswordValidationService passwordValidationService)
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty()
            .WithMessage("Current password is required");

        RuleFor(x => x.NewPassword)
            .NotEmpty()
            .WithMessage("New password is required")
            .NotEqual(x => x.CurrentPassword)
            .WithMessage("New password must be different from current password")
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
