namespace Pawthorize.Configuration;

/// <summary>
/// Operating mode for Pawthorize
/// </summary>
public enum PawthorizeMode
{
    /// <summary>
    /// Standalone mode: Auth logic runs in consumer's app
    /// Consumer provides IUserRepository, IRefreshTokenRepository
    /// </summary>
    Standalone,

    /// <summary>
    /// Platform mode: Auth logic calls Pawthorize Platform API
    /// Consumer provides Platform URL and API key
    /// </summary>
    Platform
}