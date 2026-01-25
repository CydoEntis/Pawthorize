using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pawthorize.Configuration;
using System.Threading.RateLimiting;

namespace Pawthorize.Services;

/// <summary>
/// Service for configuring ASP.NET Core rate limiting for Pawthorize endpoints.
/// </summary>
public class RateLimitingService
{
    private readonly ILogger<RateLimitingService>? _logger;

    public RateLimitingService(ILogger<RateLimitingService>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validate rate limiting configuration options.
    /// </summary>
    public void ValidateConfiguration(PawthorizeRateLimitingOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options), "Rate limiting options cannot be null.");
        }

        // Validate policy limits
        ValidatePolicy("Global", options.Global);
        ValidatePolicy("Login", options.Login);
        ValidatePolicy("Register", options.Register);
        ValidatePolicy("PasswordReset", options.PasswordReset);
        ValidatePolicy("Refresh", options.Refresh);
        ValidatePolicy("OAuth", options.OAuth);

        // Validate custom policies
        foreach (var customPolicy in options.CustomPolicies)
        {
            ValidatePolicy($"Custom:{customPolicy.Key}", customPolicy.Value);
        }

        // Validate token bucket configuration if using TokenBucket strategy
        if (options.Strategy == RateLimitingStrategy.TokenBucket)
        {
            foreach (var policy in new[] { options.Global, options.Login, options.Register, options.PasswordReset, options.Refresh, options.OAuth })
            {
                if (policy.TokensPerPeriod == null || policy.ReplenishmentPeriod == null)
                {
                    _logger?.LogWarning(
                        "TokenBucket strategy requires TokensPerPeriod and ReplenishmentPeriod to be set for all policies.");
                }
            }
        }
    }

    private void ValidatePolicy(string policyName, RateLimitPolicy policy)
    {
        if (policy == null)
        {
            throw new ArgumentNullException(nameof(policy), $"Rate limit policy '{policyName}' cannot be null.");
        }

        if (policy.PermitLimit <= 0)
        {
            throw new ArgumentException(
                $"Rate limit policy '{policyName}' must have PermitLimit > 0. Current value: {policy.PermitLimit}",
                nameof(policy));
        }

        if (policy.Window <= TimeSpan.Zero)
        {
            throw new ArgumentException(
                $"Rate limit policy '{policyName}' must have Window > TimeSpan.Zero. Current value: {policy.Window}",
                nameof(policy));
        }
    }

    /// <summary>
    /// Configure ASP.NET Core rate limiting services with Pawthorize policies.
    /// </summary>
    public void ConfigureRateLimiting(IServiceCollection services, PawthorizeRateLimitingOptions options)
    {
        if (!options.Enabled)
        {
            _logger?.LogInformation("Rate limiting is disabled. Skipping rate limiter configuration.");
            return;
        }

        services.AddRateLimiter(rateLimiterOptions =>
        {
            // Configure global policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-global", CreatePartitioner(options, options.Global));

            // Configure login policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-login", CreatePartitioner(options, options.Login));

            // Configure register policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-register", CreatePartitioner(options, options.Register));

            // Configure password reset policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-password-reset", CreatePartitioner(options, options.PasswordReset));

            // Configure refresh policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-refresh", CreatePartitioner(options, options.Refresh));

            // Configure OAuth policy
            rateLimiterOptions.AddPolicy<string>("pawthorize-oauth", CreatePartitioner(options, options.OAuth));

            // Configure custom policies
            foreach (var customPolicy in options.CustomPolicies)
            {
                rateLimiterOptions.AddPolicy<string>(customPolicy.Key, CreatePartitioner(options, customPolicy.Value));
            }

            // Configure global rate limiter options
            rateLimiterOptions.GlobalLimiter = null; // We use per-policy limiters
            rateLimiterOptions.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode = options.RateLimitStatusCode;

                if (options.IncludeRetryAfterHeader)
                {
                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    {
                        context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
                    }
                    else
                    {
                        context.HttpContext.Response.Headers.RetryAfter = "60";
                    }
                }

                await context.HttpContext.Response.WriteAsync(
                    "Rate limit exceeded. Please try again later.",
                    cancellationToken);
            };
        });

        _logger?.LogInformation("Rate limiting configured with {PolicyCount} policies.",
            6 + options.CustomPolicies.Count);
    }

    private Func<HttpContext, RateLimitPartition<string>> CreatePartitioner(
        PawthorizeRateLimitingOptions options,
        RateLimitPolicy policy)
    {
        return options.PartitionBy switch
        {
            RateLimitPartitionBy.IpAddress => ctx =>
            {
                var ipAddress = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: ipAddress,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = policy.PermitLimit,
                        Window = policy.Window,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = policy.QueueLimit
                    });
            },
            RateLimitPartitionBy.UserId => ctx =>
            {
                var userId = ctx.User?.Identity?.Name ?? ctx.Connection.Id;
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: userId,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = policy.PermitLimit,
                        Window = policy.Window,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = policy.QueueLimit
                    });
            },
            RateLimitPartitionBy.Hybrid => ctx =>
            {
                // Use UserId if authenticated, otherwise use IP address
                var partitionKey = ctx.User?.Identity?.IsAuthenticated == true
                    ? $"user:{ctx.User.Identity.Name}"
                    : $"ip:{ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: partitionKey,
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = policy.PermitLimit,
                        Window = policy.Window,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = policy.QueueLimit
                    });
            },
            _ => throw new ArgumentOutOfRangeException(nameof(options.PartitionBy), options.PartitionBy, "Unknown partition strategy")
        };
    }
}
