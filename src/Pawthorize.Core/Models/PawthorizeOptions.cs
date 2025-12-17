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

    /// <summary>
    /// Login identifier configuration (Email or Username)
    /// </summary>
    public LoginIdentifierType LoginIdentifier { get; set; } = LoginIdentifierType.Email;
}

/// <summary>
/// Type of identifier used for login
/// </summary>
public enum LoginIdentifierType
{
    /// <summary>
    /// Users log in with email address (default)
    /// </summary>
    Email,

    /// <summary>
    /// Users log in with username
    /// </summary>
    Username
}