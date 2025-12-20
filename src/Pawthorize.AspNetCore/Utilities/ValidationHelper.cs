using ErrorHound.BuiltIn;
using FluentValidation;

namespace Pawthorize.AspNetCore.Utilities;

/// <summary>
/// Helper for validating requests with FluentValidation.
/// Converts validation errors to ErrorHound ValidationError.
/// </summary>
public static class ValidationHelper
{
    /// <summary>
    /// Validate a request and throw ValidationError if invalid.
    /// </summary>
    public static async Task ValidateAndThrowAsync<TRequest>(
        TRequest request,
        IValidator<TRequest> validator,
        CancellationToken cancellationToken = default)
    {
        var validationResult = await validator.ValidateAsync(request, cancellationToken);

        if (!validationResult.IsValid)
        {
            var validationError = new ValidationError();
            foreach (var error in validationResult.Errors)
            {
                validationError.AddFieldError(error.PropertyName, error.ErrorMessage);
            }

            throw validationError;
        }
    }
}