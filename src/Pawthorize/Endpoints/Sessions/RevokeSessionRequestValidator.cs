using FluentValidation;

namespace Pawthorize.Endpoints.Sessions;

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
