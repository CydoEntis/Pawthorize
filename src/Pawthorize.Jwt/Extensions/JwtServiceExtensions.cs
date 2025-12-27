using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;
using Pawthorize.Jwt.Services;

namespace Pawthorize.Jwt.Extensions;

/// <summary>
/// Extension methods for registering JWT services.
/// </summary>
public static class JwtServiceExtensions
{
    /// <summary>
    /// Register JWT service for single-tenant mode (default).
    /// </summary>
    public static IServiceCollection AddJwtService<TUser>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TUser : IAuthenticatedUser
    {
        services.Configure<JwtSettings>(options =>
        {
            configuration.GetSection(JwtSettings.SectionName).Bind(options);
        });

        services.AddScoped<JwtService<TUser>>();

        return services;
    }

    /// <summary>
    /// Register JWT service for multi-tenant mode.
    /// Consumer must also register ITenantProvider.
    /// </summary>
    public static IServiceCollection AddJwtServiceMultiTenant<TUser>(
        this IServiceCollection services,
        IConfiguration configuration)
        where TUser : IAuthenticatedUser
    {
        services.Configure<JwtSettings>(options =>
        {
            configuration.GetSection(JwtSettings.SectionName).Bind(options);
        });

        services.AddScoped<JwtService<TUser>>();

        // Note: Consumer must register ITenantProvider themselves

        return services;
    }
}