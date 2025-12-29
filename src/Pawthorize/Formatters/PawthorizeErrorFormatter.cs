using ErrorHound.Abstractions;
using ErrorHound.BuiltIn;
using ErrorHound.Core;

namespace Pawthorize.Formatters;

/// <summary>
/// Custom error formatter for Pawthorize that matches the API response structure.
/// Ensures consistent API response format with success field, error object, and meta info.
/// Handles ValidationError field errors correctly.
/// </summary>
public class PawthorizeErrorFormatter : IErrorResponseFormatter
{
    public object Format(ApiError error)
    {
        object? details = error.Details;

        // Special handling for ValidationError to show field errors
        if (error is ValidationError validationError)
        {
            details = validationError.FieldErrors;
        }

        return new
        {
            success = false,
            error = new
            {
                code = error.Code,
                message = error.Message,
                details
            },
            meta = new
            {
                timestamp = DateTime.UtcNow.ToString("O"),
                version = "v1.0"
            }
        };
    }
}
