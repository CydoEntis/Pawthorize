using ErrorHound.BuiltIn;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace Pawthorize.Internal;

/// <summary>
/// Helper for validating requests with FluentValidation.
/// Converts validation errors to ErrorHound ValidationError.
/// This class is internal and not part of the public API.
/// </summary>
internal static class ValidationHelper
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
                var validationError = new ValidationError();
                var errorDetails = new List<string>();

                foreach (var error in validationResult.Errors)
                {
                    var fieldName = ToCamelCase(error.PropertyName);
                    validationError.AddFieldError(fieldName, error.ErrorMessage);
                    errorDetails.Add($"[{fieldName}] {error.ErrorMessage}");
                }

                logger?.LogWarning("Validation failed for {RequestType} with {ErrorCount} error(s): {ValidationErrors}",
                    requestType, errorDetails.Count, string.Join("; ", errorDetails));

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

    private static string ToCamelCase(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        return char.ToLower(name[0]) + name[1..];
    }
}
