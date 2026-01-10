namespace Pawthorize.Configuration;

/// <summary>
/// Configuration options for Pawthorize rate limiting.
/// Rate limiting is enabled by default to protect against brute force attacks,
/// credential stuffing, account enumeration, and denial of service attacks.
/// </summary>
public class PawthorizeRateLimitingOptions
{
    /// <summary>
    /// Enable or disable rate limiting.
    /// Default: true (secure by default)
    /// Warning: Disabling rate limiting exposes your application to security vulnerabilities.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Rate limiting strategy: FixedWindow, SlidingWindow, or TokenBucket.
    /// Default: FixedWindow (simplest and most predictable)
    /// </summary>
    public RateLimitingStrategy Strategy { get; set; } = RateLimitingStrategy.FixedWindow;

    /// <summary>
    /// Rate limit by IP address (default) or authenticated user.
    /// Default: IpAddress (protects unauthenticated endpoints like login and registration)
    /// </summary>
    public RateLimitPartitionBy PartitionBy { get; set; } = RateLimitPartitionBy.IpAddress;

    /// <summary>
    /// Global rate limit for all auth endpoints per partition.
    /// Default: 100 requests per minute
    /// </summary>
    public RateLimitPolicy Global { get; set; } = new()
    {
        PermitLimit = 100,
        Window = TimeSpan.FromMinutes(1)
    };

    /// <summary>
    /// Rate limit for login endpoint (strict - prevent brute force).
    /// Default: 5 attempts per 5 minutes
    /// </summary>
    public RateLimitPolicy Login { get; set; } = new()
    {
        PermitLimit = 5,
        Window = TimeSpan.FromMinutes(5)
    };

    /// <summary>
    /// Rate limit for registration endpoint (prevent spam).
    /// Default: 3 registrations per 15 minutes
    /// </summary>
    public RateLimitPolicy Register { get; set; } = new()
    {
        PermitLimit = 3,
        Window = TimeSpan.FromMinutes(15)
    };

    /// <summary>
    /// Rate limit for password reset endpoints (prevent enumeration).
    /// Default: 3 requests per 15 minutes
    /// </summary>
    public RateLimitPolicy PasswordReset { get; set; } = new()
    {
        PermitLimit = 3,
        Window = TimeSpan.FromMinutes(15)
    };

    /// <summary>
    /// Rate limit for refresh token endpoint.
    /// Default: 50 requests per 5 minutes (higher limit for normal usage)
    /// </summary>
    public RateLimitPolicy Refresh { get; set; } = new()
    {
        PermitLimit = 50,
        Window = TimeSpan.FromMinutes(5)
    };

    /// <summary>
    /// Rate limit for OAuth endpoints.
    /// Default: 10 requests per 5 minutes
    /// </summary>
    public RateLimitPolicy OAuth { get; set; } = new()
    {
        PermitLimit = 10,
        Window = TimeSpan.FromMinutes(5)
    };

    /// <summary>
    /// Custom policies for specific endpoints.
    /// Key: policy name (e.g., "custom-endpoint")
    /// Value: rate limit policy
    /// </summary>
    public Dictionary<string, RateLimitPolicy> CustomPolicies { get; set; } = new();

    /// <summary>
    /// Status code to return when rate limit is exceeded.
    /// Default: 429 (Too Many Requests)
    /// </summary>
    public int RateLimitStatusCode { get; set; } = 429;

    /// <summary>
    /// Whether to include Retry-After header in rate limit responses.
    /// Default: true
    /// </summary>
    public bool IncludeRetryAfterHeader { get; set; } = true;
}

/// <summary>
/// Configuration for a single rate limit policy.
/// </summary>
public class RateLimitPolicy
{
    private TimeSpan _window;

    /// <summary>
    /// Number of requests allowed within the window.
    /// </summary>
    public int PermitLimit { get; set; }

    /// <summary>
    /// Time window for the limit.
    /// </summary>
    public TimeSpan Window
    {
        get => _window;
        set => _window = value;
    }

    /// <summary>
    /// Time window in minutes (for configuration convenience).
    /// When set, this will override the Window property.
    /// </summary>
    public int WindowMinutes
    {
        get => (int)_window.TotalMinutes;
        set => _window = TimeSpan.FromMinutes(value);
    }

    /// <summary>
    /// Number of requests that can be queued when limit is reached.
    /// Default: 0 (reject immediately)
    /// </summary>
    public int QueueLimit { get; set; } = 0;

    /// <summary>
    /// Number of tokens per period for token bucket algorithm.
    /// Only used when Strategy is TokenBucket.
    /// </summary>
    public int? TokensPerPeriod { get; set; }

    /// <summary>
    /// Replenishment period for token bucket algorithm.
    /// Only used when Strategy is TokenBucket.
    /// </summary>
    public TimeSpan? ReplenishmentPeriod { get; set; }

    /// <summary>
    /// Replenishment period in minutes (for configuration convenience).
    /// When set, this will override the ReplenishmentPeriod property.
    /// Only used when Strategy is TokenBucket.
    /// </summary>
    public int? ReplenishmentPeriodMinutes
    {
        get => ReplenishmentPeriod.HasValue ? (int)ReplenishmentPeriod.Value.TotalMinutes : null;
        set => ReplenishmentPeriod = value.HasValue ? TimeSpan.FromMinutes(value.Value) : null;
    }
}

/// <summary>
/// Rate limiting strategy algorithms.
/// </summary>
public enum RateLimitingStrategy
{
    /// <summary>
    /// Fixed window: Count requests in fixed time windows.
    /// Simplest and most predictable.
    /// Example: 5 requests per 5-minute window starting at :00, :05, :10, etc.
    /// </summary>
    FixedWindow,

    /// <summary>
    /// Sliding window: More accurate, counts in sliding time windows.
    /// Better for preventing burst attacks.
    /// Example: 5 requests in any rolling 5-minute period.
    /// </summary>
    SlidingWindow,

    /// <summary>
    /// Token bucket: Allows bursts but enforces average rate.
    /// More flexible for legitimate usage patterns.
    /// Tokens are added at a constant rate, consumed by requests.
    /// </summary>
    TokenBucket
}

/// <summary>
/// How to partition rate limits across users.
/// </summary>
public enum RateLimitPartitionBy
{
    /// <summary>
    /// Rate limit by IP address (default).
    /// Best for protecting unauthenticated endpoints.
    /// Works for login, registration, and password reset.
    /// </summary>
    IpAddress,

    /// <summary>
    /// Rate limit by authenticated user ID.
    /// Requires authentication, doesn't protect registration/login.
    /// Use for authenticated endpoints only.
    /// </summary>
    UserId,

    /// <summary>
    /// Combination: IP for unauthenticated, UserId for authenticated.
    /// Best of both worlds - protects all endpoints appropriately.
    /// </summary>
    Hybrid
}
