using ErrorHound.Abstractions;
using ErrorHound.Core;

namespace Pawthorize.AspNetCore.Formatters;

/// <summary>
/// Custom error formatter for Pawthorize that matches the API response structure.
/// Ensures consistent API response format with success field, error object, and meta info.
/// </summary>
public class PawthorizeErrorFormatter : IErrorResponseFormatter
{
    public object Format(ApiError error)
    {
        return new
        {
            success = false,
            error = new
            {
                code = error.Code,
                message = error.Message,
                details = error.Details
            },
            meta = new
            {
                timestamp = DateTime.UtcNow.ToString("O"),
                version = "v1.0"
            }
        };
    }
}
