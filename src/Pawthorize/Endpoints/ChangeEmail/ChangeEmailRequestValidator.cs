using FluentValidation;

namespace Pawthorize.Endpoints.ChangeEmail;

/// <summary>
/// Validator for change email requests.
/// </summary>
public class ChangeEmailRequestValidator : AbstractValidator<ChangeEmailRequest>
{
    public ChangeEmailRequestValidator()
    {
        RuleFor(x => x.NewEmail)
            .NotEmpty()
            .WithMessage("New email is required")
            .EmailAddress()
            .WithMessage("New email must be a valid email address");

        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required for security confirmation");
    }
}
