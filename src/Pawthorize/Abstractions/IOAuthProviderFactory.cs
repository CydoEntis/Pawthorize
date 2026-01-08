namespace Pawthorize.Abstractions;

/// <summary>
/// Factory for resolving OAuth providers by name.
/// </summary>
public interface IOAuthProviderFactory
{
    /// <summary>
    /// Gets an OAuth provider by name (case-insensitive).
    /// </summary>
    /// <param name="providerName">The provider name (e.g., "google", "discord").</param>
    /// <returns>The OAuth provider instance.</returns>
    /// <exception cref="Errors.OAuthConfigurationError">Thrown if provider not found or not configured.</exception>
    IExternalAuthProvider GetProvider(string providerName);

    /// <summary>
    /// Gets all registered provider names.
    /// </summary>
    /// <returns>Collection of provider names.</returns>
    IEnumerable<string> GetRegisteredProviders();
}
