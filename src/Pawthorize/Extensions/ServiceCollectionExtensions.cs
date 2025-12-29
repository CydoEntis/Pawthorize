using System.Text;
using ErrorHound.BuiltIn;
using ErrorHound.Extensions;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pawthorize.Abstractions;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.Configuration;
using Pawthorize.DTOs;
using Pawthorize.Handlers;
using Pawthorize.Models;
using Pawthorize.Services;
using Pawthorize.Validators;
using SuccessHound.Extensions;

namespace Pawthorize.Extensions;

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
    /// <param name="configure">Optional action to configure response formatting</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPawthorize<TUser, TRegisterRequest>(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<PawthorizeResponseOptions>? configure = null)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        var responseOptions = new PawthorizeResponseOptions();
        configure?.Invoke(responseOptions);

        if (responseOptions.EnableSuccessHound)
        {
            ConfigureSuccessHound(services, responseOptions.SuccessFormatterType);
        }

        if (responseOptions.EnableErrorHound)
        {
            ConfigureErrorHound(services, responseOptions.ErrorFormatterType);
        }

        RegisterConfiguration(services, configuration);
        RegisterAuthentication(services, configuration);
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
        IConfiguration? configuration)
    {
        if (configuration != null)
        {
            services.Configure<PawthorizeOptions>(configuration.GetSection("Pawthorize"));
            services.Configure<JwtSettings>(configuration.GetSection("Jwt"));
        }

        services.AddOptions<PawthorizeOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<JwtSettings>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
    }

    /// <summary>
    /// Register ASP.NET Core authentication with JWT Bearer.
    /// Automatically configures OnChallenge to throw UnauthorizedError for ErrorHound integration.
    /// </summary>
    private static void RegisterAuthentication(
        IServiceCollection services,
        IConfiguration? configuration)
    {
        var serviceProvider = services.BuildServiceProvider();
        var jwtSettings = serviceProvider.GetService<IOptions<JwtSettings>>()?.Value;

        if (jwtSettings == null)
        {
            throw new InvalidOperationException(
                "JWT settings could not be loaded. Ensure configuration is provided to AddPawthorize().");
        }

        if (string.IsNullOrEmpty(jwtSettings.Secret))
        {
            throw new InvalidOperationException(
                "JWT Secret is required but not configured.");
        }

        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
                    ClockSkew = TimeSpan.Zero
                };

                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();

                        throw new UnauthorizedError(
                            string.IsNullOrEmpty(context.Error)
                                ? "Authentication required"
                                : "Invalid or expired token"
                        );
                    }
                };
            });

        services.AddAuthorization();
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
        services.AddScoped<IPasswordResetService, PasswordResetService>();
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
        services.AddScoped<ForgotPasswordHandler<TUser>>();
        services.AddScoped<ResetPasswordHandler<TUser>>();
        services.AddScoped<ChangePasswordHandler<TUser>>();
        services.AddScoped<VerifyEmailHandler<TUser>>();
        services.AddScoped<GetCurrentUserHandler<TUser>>();
        services.AddScoped<GetActiveSessionsHandler<TUser>>();
        services.AddScoped<RevokeAllOtherSessionsHandler<TUser>>();
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
        services.AddScoped<IValidator<ForgotPasswordRequest>, ForgotPasswordRequestValidator>();
        services.AddScoped<IValidator<ResetPasswordRequest>, ResetPasswordRequestValidator>();
        services.AddScoped<IValidator<ChangePasswordRequest>, ChangePasswordRequestValidator>();
        services.AddScoped<IValidator<VerifyEmailRequest>, VerifyEmailRequestValidator>();
        services.AddScoped<IValidator<RevokeAllOtherSessionsRequest>, RevokeAllOtherSessionsRequestValidator>();


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

    /// <summary>
    /// Configure SuccessHound with optional custom formatter.
    /// </summary>
    private static void ConfigureSuccessHound(IServiceCollection services, Type? formatterType)
    {
        var targetFormatterType = formatterType;

        if (targetFormatterType == null)
        {
            Type? defaultFormatterType = null;

            var possibleTypes = new[]
            {
                "SuccessHound.Defaults.DefaultSuccessFormatter, SuccessHound",
                "SuccessHound.Formatters.DefaultSuccessFormatter, SuccessHound",
                "SuccessHound.DefaultSuccessFormatter, SuccessHound"
            };

            foreach (var typeName in possibleTypes)
            {
                defaultFormatterType = Type.GetType(typeName);
                if (defaultFormatterType != null)
                    break;
            }

            if (defaultFormatterType != null)
            {
                targetFormatterType = defaultFormatterType;
            }
            else
            {
                throw new InvalidOperationException(
                    "Could not find SuccessHound's DefaultSuccessFormatter. " +
                    "Please specify a custom formatter using options.UseSuccessFormatter<T>(). " +
                    "Make sure SuccessHound package is installed.");
            }
        }

        var addSuccessHoundMethod = typeof(SuccessHoundExtensions)
            .GetMethods()
            .FirstOrDefault(m => m.Name == "AddSuccessHound" && m.GetParameters().Length == 2);

        if (addSuccessHoundMethod != null)
        {
            var optionsParam = System.Linq.Expressions.Expression.Parameter(
                addSuccessHoundMethod.GetParameters()[1].ParameterType.GetGenericArguments()[0], "options");

            var useFormatterMethod = optionsParam.Type
                .GetMethod("UseFormatter")
                ?.MakeGenericMethod(targetFormatterType);

            if (useFormatterMethod != null)
            {
                var callExpression = System.Linq.Expressions.Expression.Call(
                    optionsParam, useFormatterMethod);

                var lambda = System.Linq.Expressions.Expression.Lambda(
                    callExpression, optionsParam);

                var configAction = lambda.Compile();

                addSuccessHoundMethod.Invoke(null, new object[] { services, configAction });
                return;
            }
        }

        throw new InvalidOperationException(
            "Could not configure SuccessHound. Please ensure SuccessHound is properly installed.");
    }

    /// <summary>
    /// Configure ErrorHound with optional custom formatter.
    /// </summary>
    private static void ConfigureErrorHound(IServiceCollection services, Type? formatterType)
    {
        var targetFormatterType = formatterType;

        if (targetFormatterType == null)
        {
            Type? defaultFormatterType = null;

            var possibleTypes = new[]
            {
                "ErrorHound.Defaults.DefaultErrorFormatter, ErrorHound",
                "ErrorHound.Formatters.DefaultErrorFormatter, ErrorHound",
                "ErrorHound.DefaultErrorFormatter, ErrorHound"
            };

            foreach (var typeName in possibleTypes)
            {
                defaultFormatterType = Type.GetType(typeName);
                if (defaultFormatterType != null)
                    break;
            }

            if (defaultFormatterType != null)
            {
                targetFormatterType = defaultFormatterType;
            }
            else
            {
                throw new InvalidOperationException(
                    "Could not find ErrorHound's DefaultErrorFormatter. " +
                    "Please specify a custom formatter using options.UseErrorFormatter<T>(). " +
                    "Make sure ErrorHound package is installed.");
            }
        }

        var addErrorHoundMethod = typeof(ErrorHoundExtensions)
            .GetMethods()
            .FirstOrDefault(m => m.Name == "AddErrorHound" && m.GetParameters().Length == 2);

        if (addErrorHoundMethod != null)
        {
            var optionsParam = System.Linq.Expressions.Expression.Parameter(
                addErrorHoundMethod.GetParameters()[1].ParameterType.GetGenericArguments()[0], "options");

            var useFormatterMethod = optionsParam.Type
                .GetMethod("UseFormatter")
                ?.MakeGenericMethod(targetFormatterType);

            if (useFormatterMethod != null)
            {
                var callExpression = System.Linq.Expressions.Expression.Call(
                    optionsParam, useFormatterMethod);

                var lambda = System.Linq.Expressions.Expression.Lambda(
                    callExpression, optionsParam);

                var configAction = lambda.Compile();

                addErrorHoundMethod.Invoke(null, new object[] { services, configAction });
                return;
            }
        }

        throw new InvalidOperationException(
            "Could not configure ErrorHound. Please ensure ErrorHound is properly installed.");
    }
}