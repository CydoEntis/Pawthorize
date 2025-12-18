using FluentValidation;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.Core.Models;

namespace Pawthorize.AspNetCore.Validators;

/// <summary>
/// Optional login validator with format validation.
/// Validates identifier format based on LoginIdentifierType configuration.
/// Provides better UX with early feedback, but reveals format expectations.
/// Use this if UX is more important than hiding format requirements.
/// </summary>
public class FormatValidatingLoginRequestValidator : AbstractValidator<LoginRequest>
{
    public FormatValidatingLoginRequestValidator(IOptions<PawthorizeOptions> options)
    {
        Include(new LoginRequestValidator());

        switch (options.Value.LoginIdentifier)
        {
            case LoginIdentifierType.Email:
                RuleFor(x => x.Identifier)
                    .EmailAddress()
                    .WithMessage("Please provide a valid email address");
                break;

            case LoginIdentifierType.Username:
                RuleFor(x => x.Identifier)
                    .Matches(@"^[a-zA-Z0-9_-]{3,30}$")
                    .WithMessage(
                        "Username must be 3-30 characters and contain only letters, numbers, hyphens, and underscores");
                break;

            case LoginIdentifierType.Phone:
                RuleFor(x => x.Identifier)
                    .Matches(@"^\+?[1-9]\d{1,14}$")
                    .WithMessage("Phone number must be in E.164 format (e.g., +12025551234)");
                break;
        }
    }
}