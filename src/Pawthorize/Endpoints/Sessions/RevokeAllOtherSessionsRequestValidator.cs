using FluentValidation;

namespace Pawthorize.Endpoints.Sessions;

/// <summary>
/// Validator for revoke all other sessions requests.
/// Note: RefreshToken is optional in the request body as it may be provided via cookie.
/// </summary>
public class RevokeAllOtherSessionsRequestValidator : AbstractValidator<RevokeAllOtherSessionsRequest>
{
    public RevokeAllOtherSessionsRequestValidator()
    {
        // RefreshToken is optional because it can come from cookie
        // If provided in body, it must be valid format
        When(x => !string.IsNullOrEmpty(x.RefreshToken), () =>
        {
            RuleFor(x => x.RefreshToken)
                .MinimumLength(64)
                .WithMessage("Invalid refresh token format");
        });
    }
}
