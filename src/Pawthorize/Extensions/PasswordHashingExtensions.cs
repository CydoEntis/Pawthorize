using Microsoft.Extensions.DependencyInjection;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Services;

namespace Pawthorize.Extensions;

/// <summary>
/// Extension methods for registering password hashing services.
/// </summary>
public static class PasswordHashingExtensions
{
    /// <summary>
    /// Register password hashing with default work factor (12).
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPasswordHashing(
        this IServiceCollection services)
    {
        services.AddSingleton<IPasswordHasher>(new PasswordHasher(workFactor: 12));
        return services;
    }

    /// <summary>
    /// Register password hashing with custom work factor.
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="workFactor">BCrypt work factor (10-14 recommended)</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPasswordHashing(
        this IServiceCollection services,
        int workFactor)
    {
        services.AddSingleton<IPasswordHasher>(new PasswordHasher(workFactor));
        return services;
    }

    /// <summary>
    /// Register password hashing with work factor from configuration.
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Configuration action</param>
    /// <returns>Service collection for chaining</returns>
    /// <remarks>
    /// Reads work factor from PawthorizeOptions.
    /// Defaults to 12 if not configured.
    /// </remarks>
    public static IServiceCollection AddPasswordHashingFromConfig(
        this IServiceCollection services,
        Action<PasswordHashingOptions> configure)
    {
        var options = new PasswordHashingOptions();
        configure(options);

        services.AddSingleton<IPasswordHasher>(new PasswordHasher(options.WorkFactor));
        return services;
    }
}