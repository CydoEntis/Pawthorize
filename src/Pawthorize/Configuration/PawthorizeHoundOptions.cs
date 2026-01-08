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
    internal bool EnableOAuth { get; private set; }
    internal List<OAuthProviderRegistration> OAuthProviders { get; private set; } = new();

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

    /// <summary>
    /// Enable Google OAuth authentication.
    /// Requires configuration in appsettings.json under Pawthorize:OAuth:Providers:Google.
    /// </summary>
    public PawthorizeResponseOptions AddGoogle()
    {
        EnableOAuth = true;
        OAuthProviders.Add(new OAuthProviderRegistration
        {
            ProviderName = "google",
            ProviderType = typeof(Providers.GoogleOAuthProvider)
        });
        return this;
    }

    /// <summary>
    /// Enable Discord OAuth authentication.
    /// Requires configuration in appsettings.json under Pawthorize:OAuth:Providers:Discord.
    /// </summary>
    public PawthorizeResponseOptions AddDiscord()
    {
        EnableOAuth = true;
        OAuthProviders.Add(new OAuthProviderRegistration
        {
            ProviderName = "discord",
            ProviderType = typeof(Providers.DiscordOAuthProvider)
        });
        return this;
    }

    /// <summary>
    /// Add a custom OAuth provider.
    /// </summary>
    /// <typeparam name="TProvider">Provider type implementing IExternalAuthProvider</typeparam>
    /// <param name="providerName">Provider name (e.g., "github", "facebook")</param>
    public PawthorizeResponseOptions AddCustomOAuthProvider<TProvider>(string providerName)
        where TProvider : Abstractions.IExternalAuthProvider
    {
        EnableOAuth = true;
        OAuthProviders.Add(new OAuthProviderRegistration
        {
            ProviderName = providerName.ToLowerInvariant(),
            ProviderType = typeof(TProvider)
        });
        return this;
    }
}

/// <summary>
/// Internal class to track OAuth provider registrations.
/// </summary>
internal class OAuthProviderRegistration
{
    public required string ProviderName { get; init; }
    public required Type ProviderType { get; init; }
}
