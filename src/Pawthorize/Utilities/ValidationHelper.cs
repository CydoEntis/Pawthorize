using ErrorHound.BuiltIn;
using FluentValidation;
using Microsoft.Extensions.Logging;

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
        CancellationToken cancellationToken = default,
        ILogger? logger = null)
    {
        var requestType = typeof(TRequest).Name;
        logger?.LogDebug("Validating {RequestType} request", requestType);

        try
        {
            var validationResult = await validator.ValidateAsync(request, cancellationToken);

            if (!validationResult.IsValid)
            {
                var errorCount = validationResult.Errors.Count;
                logger?.LogWarning("Validation failed for {RequestType} with {ErrorCount} error(s)",
                    requestType, errorCount);

                var validationError = new ValidationError();
                foreach (var error in validationResult.Errors)
                {
                    validationError.AddFieldError(error.PropertyName, error.ErrorMessage);
                    logger?.LogDebug("Validation error - Field: {PropertyName}, Message: {ErrorMessage}",
                        error.PropertyName, error.ErrorMessage);
                }

                throw validationError;
            }

            logger?.LogDebug("Validation passed for {RequestType}", requestType);
        }
        catch (ValidationError)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Unexpected error during validation of {RequestType}", requestType);
            throw;
        }
    }
}