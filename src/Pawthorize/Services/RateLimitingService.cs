using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pawthorize.Configuration;
using Microsoft.AspNetCore.Builder;

namespace Pawthorize.Services;

/// <summary>
/// Service responsible for configuring ASP.NET Core rate limiting for Pawthorize endpoints.
/// Integrates with the built-in rate limiting middleware (.NET 7+).
/// </summary>
public class RateLimitingService
{
    private readonly ILogger<RateLimitingService>? _logger;

    public RateLimitingService(ILogger<RateLimitingService>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Configure rate limiting for Pawthorize endpoints.
    /// Creates named policies that can be applied to endpoints or reused by users.
    /// </summary>
    public void ConfigureRateLimiting(
        IServiceCollection services,
        PawthorizeRateLimitingOptions options)
    {
        if (!options.Enabled)
        {
            _logger?.LogInformation("Rate limiting is disabled via configuration");
            return;
        }

        _logger?.LogInformation("Configuring rate limiting with {Strategy} strategy and {PartitionBy} partitioning",
            options.Strategy, options.PartitionBy);

        services.AddRateLimiter(rateLimiterOptions =>
        {
            // Configure global rejection behavior
            rateLimiterOptions.RejectionStatusCode = options.RateLimitStatusCode;

            rateLimiterOptions.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = options.RateLimitStatusCode;

                TimeSpan? retryAfter = null;
                if (options.IncludeRetryAfterHeader && context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfterValue))
                {
                    retryAfter = retryAfterValue;
                    context.HttpContext.Response.Headers.RetryAfter =
                        ((int)retryAfterValue.TotalSeconds).ToString(NumberFormatInfo.InvariantInfo);
                }

                _logger?.LogWarning(
                    "Rate limit exceeded for {Endpoint} from {IP}",
                    context.HttpContext.Request.Path,
                    GetClientIp(context.HttpContext));

                await context.HttpContext.Response.WriteAsJsonAsync(new
                {
                    error = "Rate limit exceeded",
                    message = "Too many requests. Please try again later.",
                    retryAfter = retryAfter?.TotalSeconds
                }, cancellationToken);
            };

            // Create named policies for each endpoint type
            AddPolicy(rateLimiterOptions, "pawthorize-global", options.Global, options);
            AddPolicy(rateLimiterOptions, "pawthorize-login", options.Login, options);
            AddPolicy(rateLimiterOptions, "pawthorize-register", options.Register, options);
            AddPolicy(rateLimiterOptions, "pawthorize-password-reset", options.PasswordReset, options);
            AddPolicy(rateLimiterOptions, "pawthorize-refresh", options.Refresh, options);
            AddPolicy(rateLimiterOptions, "pawthorize-oauth", options.OAuth, options);

            // Add custom policies
            foreach (var (policyName, policy) in options.CustomPolicies)
            {
                AddPolicy(rateLimiterOptions, $"pawthorize-{policyName}", policy, options);
            }

            _logger?.LogInformation(
                "Rate limiting configured with {PolicyCount} policies. Default limits: Login={LoginLimit}/{LoginWindow}, Register={RegisterLimit}/{RegisterWindow}",
                6 + options.CustomPolicies.Count,
                options.Login.PermitLimit,
                options.Login.Window,
                options.Register.PermitLimit,
                options.Register.Window);
        });
    }

    /// <summary>
    /// Add a named rate limiting policy.
    /// </summary>
    private void AddPolicy(
        RateLimiterOptions rateLimiterOptions,
        string policyName,
        RateLimitPolicy policy,
        PawthorizeRateLimitingOptions globalOptions)
    {
        rateLimiterOptions.AddPolicy(policyName, context =>
        {
            var partitionKey = GetPartitionKey(context, globalOptions.PartitionBy);

            return globalOptions.Strategy switch
            {
                RateLimitingStrategy.FixedWindow => RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = policy.PermitLimit,
                        Window = policy.Window,
                        QueueLimit = policy.QueueLimit
                    }),

                RateLimitingStrategy.SlidingWindow => RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey,
                    _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = policy.PermitLimit,
                        Window = policy.Window,
                        QueueLimit = policy.QueueLimit,
                        SegmentsPerWindow = 8 // Divide window into 8 segments for better accuracy
                    }),

                RateLimitingStrategy.TokenBucket => RateLimitPartition.GetTokenBucketLimiter(
                    partitionKey,
                    _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = policy.PermitLimit,
                        TokensPerPeriod = policy.TokensPerPeriod ?? policy.PermitLimit,
                        ReplenishmentPeriod = policy.ReplenishmentPeriod ?? policy.Window,
                        QueueLimit = policy.QueueLimit
                    }),

                _ => throw new NotSupportedException($"Rate limiting strategy '{globalOptions.Strategy}' is not supported")
            };
        });
    }

    /// <summary>
    /// Get the partition key based on the partitioning strategy.
    /// </summary>
    private string GetPartitionKey(HttpContext context, RateLimitPartitionBy partitionBy)
    {
        return partitionBy switch
        {
            RateLimitPartitionBy.IpAddress => GetClientIp(context),

            RateLimitPartitionBy.UserId => context.User.Identity?.IsAuthenticated == true
                ? context.User.FindFirst("sub")?.Value ?? GetClientIp(context)
                : GetClientIp(context),

            RateLimitPartitionBy.Hybrid => context.User.Identity?.IsAuthenticated == true
                ? $"user:{context.User.FindFirst("sub")?.Value}"
                : $"ip:{GetClientIp(context)}",

            _ => GetClientIp(context)
        };
    }

    /// <summary>
    /// Extract client IP address from HttpContext.
    /// Handles proxy headers (X-Forwarded-For, X-Real-IP).
    /// </summary>
    private string GetClientIp(HttpContext context)
    {
        // Check X-Forwarded-For header (set by proxies/load balancers)
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // Use the first one (original client)
            var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
            if (ips.Length > 0)
            {
                return ips[0].Trim();
            }
        }

        // Check X-Real-IP header (alternative proxy header)
        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp.Trim();
        }

        // Fall back to RemoteIpAddress
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    /// <summary>
    /// Validate rate limiting configuration.
    /// </summary>
    public void ValidateConfiguration(PawthorizeRateLimitingOptions options)
    {
        if (!options.Enabled)
        {
            _logger?.LogWarning(
                "Rate limiting is DISABLED. Your application is vulnerable to brute force attacks, " +
                "credential stuffing, and denial of service attacks. Enable rate limiting in production.");
            return;
        }

        ValidatePolicy("Global", options.Global);
        ValidatePolicy("Login", options.Login);
        ValidatePolicy("Register", options.Register);
        ValidatePolicy("PasswordReset", options.PasswordReset);
        ValidatePolicy("Refresh", options.Refresh);
        ValidatePolicy("OAuth", options.OAuth);

        foreach (var (name, policy) in options.CustomPolicies)
        {
            ValidatePolicy(name, policy);
        }

        // Warn if login limits are too permissive
        if (options.Login.PermitLimit > 20)
        {
            _logger?.LogWarning(
                "Login rate limit is very high ({Limit} requests per {Window}). " +
                "Consider a lower limit (e.g., 5-10 per 5 minutes) for better security against brute force attacks.",
                options.Login.PermitLimit,
                options.Login.Window);
        }

        // Warn if using UserId partitioning (doesn't protect unauthenticated endpoints)
        if (options.PartitionBy == RateLimitPartitionBy.UserId)
        {
            _logger?.LogWarning(
                "Rate limiting is configured to partition by UserId. " +
                "This DOES NOT protect unauthenticated endpoints like login and registration. " +
                "Consider using IpAddress or Hybrid partitioning for better security.");
        }
    }

    /// <summary>
    /// Validate a single rate limit policy.
    /// </summary>
    private void ValidatePolicy(string name, RateLimitPolicy policy)
    {
        if (policy.PermitLimit <= 0)
        {
            throw new InvalidOperationException(
                $"Rate limit policy '{name}' has invalid PermitLimit: {policy.PermitLimit}. Must be greater than 0.");
        }

        if (policy.Window <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"Rate limit policy '{name}' has invalid Window: {policy.Window}. Must be greater than 0.");
        }

        if (policy.QueueLimit < 0)
        {
            throw new InvalidOperationException(
                $"Rate limit policy '{name}' has invalid QueueLimit: {policy.QueueLimit}. Must be >= 0.");
        }
    }
}
