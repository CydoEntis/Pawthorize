using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;

namespace Pawthorize.Services;

/// <summary>
/// Factory for resolving OAuth providers by name.
/// </summary>
public class OAuthProviderFactory : IOAuthProviderFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<OAuthProviderFactory> _logger;
    private readonly Dictionary<string, Type> _registeredProviders = new();

    public OAuthProviderFactory(
        IServiceProvider serviceProvider,
        ILogger<OAuthProviderFactory> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public void RegisterProvider<TProvider>(string providerName) where TProvider : IExternalAuthProvider
    {
        var normalizedName = providerName.ToLowerInvariant();
        _registeredProviders[normalizedName] = typeof(TProvider);
        _logger.LogDebug("Registered OAuth provider: {ProviderName} -> {ProviderType}",
            providerName, typeof(TProvider).Name);
    }

    public IExternalAuthProvider GetProvider(string providerName)
    {
        var normalizedName = providerName.ToLowerInvariant();

        if (!_registeredProviders.TryGetValue(normalizedName, out var providerType))
        {
            _logger.LogError("OAuth provider '{ProviderName}' is not registered", providerName);
            throw new OAuthConfigurationError(
                $"OAuth provider '{providerName}' is not registered or supported.",
                $"Supported providers: {string.Join(", ", _registeredProviders.Keys)}");
        }

        var provider = _serviceProvider.GetService(providerType) as IExternalAuthProvider;

        if (provider == null)
        {
            _logger.LogError("Failed to resolve OAuth provider '{ProviderName}' from DI container", providerName);
            throw new OAuthConfigurationError(
                $"OAuth provider '{providerName}' is registered but could not be resolved.",
                "Ensure the provider is properly registered in the DI container");
        }

        _logger.LogDebug("Resolved OAuth provider: {ProviderName}", providerName);

        return provider;
    }

    public IEnumerable<string> GetRegisteredProviders()
    {
        return _registeredProviders.Keys;
    }
}
