using FluentValidation;

namespace Pawthorize.Endpoints.VerifyEmail;

/// <summary>
/// Validator for verify email requests.
/// </summary>
public class VerifyEmailRequestValidator : AbstractValidator<VerifyEmailRequest>
{
    public VerifyEmailRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty()
            .WithMessage("Verification token is required");
    }
}
