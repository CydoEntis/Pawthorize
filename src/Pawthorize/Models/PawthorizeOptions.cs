namespace Pawthorize.Models;

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

    /// <summary>
    /// CSRF protection configuration.
    /// Automatically enabled for HttpOnlyCookies and Hybrid token delivery modes.
    /// </summary>
    public CsrfOptions Csrf { get; set; } = new();
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

/// <summary>
/// CSRF protection configuration options
/// </summary>
public class CsrfOptions
{
    /// <summary>
    /// Enable or disable CSRF protection.
    /// Default: Automatically enabled for HttpOnlyCookies and Hybrid modes.
    /// Warning: Disabling CSRF protection when using cookies creates a security vulnerability.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Name of the cookie that stores the CSRF token.
    /// This cookie is NOT HttpOnly so JavaScript can read it.
    /// Default: "XSRF-TOKEN"
    /// </summary>
    public string CookieName { get; set; } = "XSRF-TOKEN";

    /// <summary>
    /// Name of the header that clients must send with the CSRF token.
    /// Default: "X-XSRF-TOKEN"
    /// </summary>
    public string HeaderName { get; set; } = "X-XSRF-TOKEN";

    /// <summary>
    /// Paths that should be excluded from CSRF validation.
    /// Login and register endpoints are always excluded automatically.
    /// Format: "/api/public/endpoint"
    /// </summary>
    public List<string> ExcludedPaths { get; set; } = new();

    /// <summary>
    /// CSRF token lifetime in minutes.
    /// Should match or exceed the refresh token lifetime.
    /// Default: 10080 minutes (7 days)
    /// </summary>
    public int TokenLifetimeMinutes { get; set; } = 10080;
}