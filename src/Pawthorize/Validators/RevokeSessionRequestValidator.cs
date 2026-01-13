using FluentValidation;
using Pawthorize.DTOs;

namespace Pawthorize.Validators;

/// <summary>
/// Validator for RevokeSessionRequest
/// </summary>
public class RevokeSessionRequestValidator : AbstractValidator<RevokeSessionRequest>
{
    public RevokeSessionRequestValidator()
    {
        RuleFor(x => x.SessionId)
            .NotEmpty()
            .WithMessage("SessionId is required");
    }
}
