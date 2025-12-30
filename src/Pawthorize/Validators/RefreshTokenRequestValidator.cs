using FluentValidation;
using Microsoft.Extensions.Options;
using Pawthorize.DTOs;
using Pawthorize.Models;

namespace Pawthorize.Validators;

/// <summary>
/// Validator for refresh token requests.
/// In Hybrid/HttpOnlyCookies mode, the refresh token comes from cookies, so the body field is optional.
/// In ResponseBody mode, the refresh token must be in the request body.
/// </summary>
public class RefreshTokenRequestValidator : AbstractValidator<RefreshTokenRequest>
{
    public RefreshTokenRequestValidator(IOptions<PawthorizeOptions> options)
    {
        var tokenDelivery = options.Value.TokenDelivery;

        // Only validate the body field if using ResponseBody mode
        // In Hybrid/HttpOnlyCookies mode, the refresh token comes from cookies
        if (tokenDelivery == TokenDeliveryStrategy.ResponseBody)
        {
            RuleFor(x => x.RefreshToken)
                .NotEmpty()
                .WithMessage("Refresh token is required")
                .MinimumLength(64)
                .WithMessage("Invalid refresh token format");
        }
    }
}