using FluentValidation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.AspNetCore.Services;
using Pawthorize.AspNetCore.Validators;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;
using Pawthorize.Jwt.Services;
using Pawthorize.Security.Services;

namespace Pawthorize.AspNetCore.Extensions;

/// <summary>
/// Extension methods for registering Pawthorize services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Register all Pawthorize services, handlers, and validators.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <typeparam name="TRegisterRequest">Registration request type (can be extended)</typeparam>
    /// <param name="services">Service collection</param>
    /// <param name="configuration">Configuration root (optional - reads from "Pawthorize" section)</param>
    /// <param name="configureOptions">Optional action to configure PawthorizeOptions</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPawthorize<TUser, TRegisterRequest>(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<PawthorizeOptions>? configureOptions = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        RegisterConfiguration(services, configuration, configureOptions);
        RegisterCoreServices<TUser>(services);
        RegisterHandlers<TUser, TRegisterRequest>(services);
        RegisterValidators<TRegisterRequest>(services);
        ValidateConfiguration(services);

        return services;
    }

    /// <summary>
    /// Register configuration options.
    /// </summary>
    private static void RegisterConfiguration(
        IServiceCollection services,
        IConfiguration? configuration,
        Action<PawthorizeOptions>? configureOptions)
    {
        if (configuration != null)
        {
            services.Configure<PawthorizeOptions>(configuration.GetSection("Pawthorize"));
            services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        }

        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }

        services.AddOptions<PawthorizeOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<JwtSettings>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
    }

    /// <summary>
    /// Register core authentication services.
    /// </summary>
    private static void RegisterCoreServices<TUser>(IServiceCollection services)
        where TUser : class, IAuthenticatedUser
    {
        services.AddScoped<IPasswordHasher, PasswordHasher>();
        services.AddScoped<JwtService<TUser>>();
        services.AddScoped<AuthenticationService<TUser>>();
    }

    /// <summary>
    /// Register all authentication handlers.
    /// </summary>
    private static void RegisterHandlers<TUser, TRegisterRequest>(IServiceCollection services)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        services.AddScoped<LoginHandler<TUser>>();
        services.AddScoped<RegisterHandler<TUser, TRegisterRequest>>();
        services.AddScoped<RefreshHandler<TUser>>();
        services.AddScoped<LogoutHandler<TUser>>();
    }

    /// <summary>
    /// Register FluentValidation validators.
    /// </summary>
    private static void RegisterValidators<TRegisterRequest>(IServiceCollection services)
        where TRegisterRequest : RegisterRequest
    {
        services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
        services.AddScoped<IValidator<RefreshTokenRequest>, RefreshTokenRequestValidator>();
        services.AddScoped<IValidator<LogoutRequest>, LogoutRequestValidator>();
        services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();


        if (typeof(TRegisterRequest) != typeof(RegisterRequest))
        {
            services.AddScoped(typeof(IValidator<TRegisterRequest>), serviceProvider =>
            {
                var existingValidator = serviceProvider.GetService<IValidator<TRegisterRequest>>();
                if (existingValidator != null)
                    return existingValidator;

                return serviceProvider.GetRequiredService<IValidator<RegisterRequest>>();
            });
        }
    }

    /// <summary>
    /// Validate configuration on startup.
    /// </summary>
    private static void ValidateConfiguration(IServiceCollection services)
    {
        var serviceProvider = services.BuildServiceProvider();

        try
        {
            var pawthorizeOptions = serviceProvider.GetRequiredService<IOptions<PawthorizeOptions>>().Value;
            var jwtSettings = serviceProvider.GetRequiredService<IOptions<JwtSettings>>().Value;

            if (string.IsNullOrEmpty(jwtSettings.Secret))
            {
                throw new InvalidOperationException(
                    "JWT Secret is not configured. " +
                    "Set 'Jwt:Secret' in appsettings.json or configure via options.");
            }

            if (jwtSettings.Secret.Length < 32)
            {
                throw new InvalidOperationException(
                    $"JWT Secret must be at least 32 characters. Current length: {jwtSettings.Secret.Length}");
            }

            if (pawthorizeOptions.RequireEmailVerification)
            {
                if (string.IsNullOrEmpty(pawthorizeOptions.EmailVerification.BaseUrl))
                {
                    throw new InvalidOperationException(
                        "Email verification is enabled but BaseUrl is not configured. " +
                        "Set 'Pawthorize:EmailVerification:BaseUrl' in appsettings.json.");
                }

                var emailService = serviceProvider.GetService<IEmailVerificationService>();
                if (emailService == null)
                {
                    throw new InvalidOperationException(
                        "Email verification is enabled but IEmailVerificationService is not registered. " +
                        "Register IEmailVerificationService in your DI container.");
                }
            }
        }
        finally
        {
            if (serviceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}