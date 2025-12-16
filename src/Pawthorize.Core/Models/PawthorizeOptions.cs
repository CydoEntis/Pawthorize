namespace Pawthorize.Core.Models;

/// <summary>
/// Main configuration options for Pawthorize.
/// Used by both standalone library and server modes.
/// </summary>
public class PawthorizeOptions
{
    /// <summary>
    /// JWT settings (token generation and validation)
    /// </summary>
    public JwtSettings Jwt { get; set; } = new();

    /// <summary>
    /// Password hashing settings
    /// </summary>
    public PasswordHashingOptions PasswordHashing { get; set; } = new();

    /// <summary>
    /// Mode: Standalone (embedded) or Platform (server)
    /// </summary>
    public PawthorizeMode Mode { get; set; } = PawthorizeMode.Standalone;

    /// <summary>
    /// Platform-specific settings (only used in Platform mode)
    /// </summary>
    public PlatformOptions? Platform { get; set; }
}