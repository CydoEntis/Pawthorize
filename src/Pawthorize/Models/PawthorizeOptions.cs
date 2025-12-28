namespace Pawthorize.Core.Models;

/// <summary>
/// Main configuration options for Pawthorize.
/// </summary>
public class PawthorizeOptions
{
    /// <summary>
    /// JWT token configuration
    /// </summary>
    public JwtSettings Jwt { get; set; } = new();

    /// <summary>
    /// Password hashing configuration
    /// </summary>
    public PasswordHashingOptions PasswordHashing { get; set; } = new();

    /// <summary>
    /// Pawthorize mode (Standalone or Platform)
    /// </summary>
    public PawthorizeMode Mode { get; set; } = PawthorizeMode.Standalone;

    /// <summary>
    /// Platform connection settings (only for Platform mode)
    /// </summary>
    public PlatformOptions? Platform { get; set; }

    /// <summary>
    /// Type of identifier to use for login (Email, Username, Phone)
    /// Default: Email
    /// </summary>
    public LoginIdentifierType LoginIdentifier { get; set; } = LoginIdentifierType.Email;

    /// <summary>
    /// How tokens should be delivered to the client
    /// Default: Hybrid (access token in body, refresh token in cookie)
    /// </summary>
    public TokenDeliveryStrategy TokenDelivery { get; set; } = TokenDeliveryStrategy.Hybrid;

    /// <summary>
    /// Whether to require email verification before allowing login.
    /// If true, users must verify their email before they can log in.
    /// Default: false
    /// </summary>
    public bool RequireEmailVerification { get; set; } = false;

    /// <summary>
    /// Email verification configuration (optional).
    /// Only used if RequireEmailVerification is true.
    /// </summary>
    public EmailVerificationOptions EmailVerification { get; set; } = new();

    /// <summary>
    /// Password reset configuration (optional).
    /// Used for forgot password / reset password flows.
    /// </summary>
    public PasswordResetOptions PasswordReset { get; set; } = new();
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
    Username,

    /// <summary>
    /// Users log in with phone number
    /// </summary>
    Phone
}

/// <summary>
/// Strategy for delivering authentication tokens to the client
/// </summary>
public enum TokenDeliveryStrategy
{
    /// <summary>
    /// Both access and refresh tokens in response body (JSON).
    /// Use for: Mobile apps, desktop apps, or when cookies aren't suitable.
    /// Security: Less secure - tokens accessible to JavaScript.
    /// </summary>
    ResponseBody,

    /// <summary>
    /// Both access and refresh tokens in HttpOnly cookies.
    /// Use for: Server-rendered apps or when maximum security is needed.
    /// Security: More secure - tokens not accessible to JavaScript.
    /// Note: Requires proper CORS configuration.
    /// </summary>
    HttpOnlyCookies,

    /// <summary>
    /// Access token in response body, refresh token in HttpOnly cookie (default).
    /// Use for: Single-page applications (SPAs).
    /// Security: Balanced - access token accessible for API calls, refresh token protected.
    /// This is the recommended approach for most web applications.
    /// </summary>
    Hybrid
}