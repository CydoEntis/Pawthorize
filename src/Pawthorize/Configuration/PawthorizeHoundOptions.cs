using Microsoft.Extensions.Configuration;

namespace Pawthorize.Configuration;

/// <summary>
/// Options for configuring response formatting with Pawthorize.
/// </summary>
public sealed class PawthorizeResponseOptions
{
    internal bool EnableSuccessHound { get; private set; }
    internal bool EnableErrorHound { get; private set; }
    internal Type? SuccessFormatterType { get; private set; }
    internal Type? ErrorFormatterType { get; private set; }
    internal IConfiguration? Configuration { get; private set; }

    /// <summary>
    /// Load Pawthorize configuration from appsettings.json (IConfiguration).
    /// Reads from "Pawthorize" and "Jwt" configuration sections.
    /// </summary>
    /// <param name="configuration">The application configuration (typically builder.Configuration)</param>
    public PawthorizeResponseOptions UseConfiguration(IConfiguration configuration)
    {
        Configuration = configuration;
        return this;
    }

    /// <summary>
    /// Use default formatters for success and error responses.
    /// This ensures consistent API response format across success and error cases.
    /// Uses ErrorHound's DefaultErrorFormatter which automatically handles ValidationError field errors.
    /// </summary>
    public PawthorizeResponseOptions UseDefaultFormatters()
    {
        EnableSuccessHound = true;
        EnableErrorHound = true;
        // Use ErrorHound's built-in DefaultErrorFormatter (null = use default)
        ErrorFormatterType = null;
        return this;
    }

    /// <summary>
    /// Configure a custom success response formatter.
    /// </summary>
    /// <typeparam name="TFormatter">Type implementing ISuccessResponseFormatter</typeparam>
    public PawthorizeResponseOptions UseSuccessFormatter<TFormatter>() where TFormatter : class
    {
        EnableSuccessHound = true;
        SuccessFormatterType = typeof(TFormatter);
        return this;
    }

    /// <summary>
    /// Configure a custom error response formatter.
    /// </summary>
    /// <typeparam name="TFormatter">Type implementing IErrorResponseFormatter</typeparam>
    public PawthorizeResponseOptions UseErrorFormatter<TFormatter>() where TFormatter : class
    {
        EnableErrorHound = true;
        ErrorFormatterType = typeof(TFormatter);
        return this;
    }
}
