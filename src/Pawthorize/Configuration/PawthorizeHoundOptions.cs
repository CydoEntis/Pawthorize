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

    /// <summary>
    /// Use default formatters for success and error responses.
    /// This ensures consistent API response format across success and error cases.
    /// Uses ErrorHound's DefaultErrorFormatter which automatically handles ValidationError field errors.
    /// </summary>
    public void UseDefaultFormatters()
    {
        EnableSuccessHound = true;
        EnableErrorHound = true;
        // Use ErrorHound's built-in DefaultErrorFormatter (null = use default)
        ErrorFormatterType = null;
    }

    /// <summary>
    /// Configure a custom success response formatter.
    /// </summary>
    /// <typeparam name="TFormatter">Type implementing ISuccessResponseFormatter</typeparam>
    public void UseSuccessFormatter<TFormatter>() where TFormatter : class
    {
        EnableSuccessHound = true;
        SuccessFormatterType = typeof(TFormatter);
    }

    /// <summary>
    /// Configure a custom error response formatter.
    /// </summary>
    /// <typeparam name="TFormatter">Type implementing IErrorResponseFormatter</typeparam>
    public void UseErrorFormatter<TFormatter>() where TFormatter : class
    {
        EnableErrorHound = true;
        ErrorFormatterType = typeof(TFormatter);
    }
}
