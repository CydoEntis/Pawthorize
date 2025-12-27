namespace Pawthorize.AspNetCore.Configuration;

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
    /// This is the recommended approach for most applications.
    /// </summary>
    public void UseDefaultFormatters()
    {
        EnableSuccessHound = true;
        EnableErrorHound = true;
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
