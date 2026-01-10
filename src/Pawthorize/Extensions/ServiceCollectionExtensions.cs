using System.Text;
using ErrorHound.BuiltIn;
using ErrorHound.Extensions;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
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
    /// Uses the default RegisterRequest type.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Action to configure response formatting</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPawthorize<TUser>(
        this IServiceCollection services,
        Action<PawthorizeResponseOptions> configure)
        where TUser : class, IAuthenticatedUser
    {
        return AddPawthorize<TUser, RegisterRequest>(services, configure);
    }

    /// <summary>
    /// Register all Pawthorize services, handlers, and validators with a custom registration request type.
    /// </summary>
    /// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
    /// <typeparam name="TRegisterRequest">Registration request type (can be extended)</typeparam>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Action to configure response formatting</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddPawthorize<TUser, TRegisterRequest>(
        this IServiceCollection services,
        Action<PawthorizeResponseOptions> configure)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : RegisterRequest
    {
        var responseOptions = new PawthorizeResponseOptions();
        configure.Invoke(responseOptions);

        services.AddSingleton(new PawthorizeTypeMetadata(typeof(TUser), typeof(TRegisterRequest), responseOptions.EnableOAuth));

        if (responseOptions.EnableSuccessHound)
        {
            ConfigureSuccessHound(services, responseOptions.SuccessFormatterType);
        }

        if (responseOptions.EnableErrorHound)
        {
            ConfigureErrorHound(services, responseOptions.ErrorFormatterType);
        }

        RegisterConfiguration(services, responseOptions.Configuration);
        RegisterAuthentication(services, responseOptions.Configuration);
        RegisterCoreServices<TUser>(services);
        RegisterHandlers<TUser, TRegisterRequest>(services);
        RegisterValidators<TRegisterRequest>(services);

        // Register OAuth if enabled
        if (responseOptions.EnableOAuth)
        {
            RegisterOAuth<TUser>(services, responseOptions);
        }

        // Register rate limiting
        RegisterRateLimiting(services, responseOptions.Configuration);

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
            services.Configure<Configuration.PasswordPolicyOptions>(configuration.GetSection("Pawthorize:PasswordPolicy"));
            services.Configure<Configuration.AccountLockoutOptions>(configuration.GetSection("Pawthorize:AccountLockout"));
        }

        services.AddOptions<PawthorizeOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<JwtSettings>()
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<Configuration.PasswordPolicyOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<Configuration.AccountLockoutOptions>()
            .ValidateDataAnnotations()
            .ValidateOnStart();
    }

    /// <summary>
    /// Register ASP.NET Core authentication with JWT Bearer.
    /// Automatically configures OnChallenge to throw UnauthorizedError for ErrorHound integration.
    /// Configures cookie policy and token extraction based on TokenDeliveryStrategy.
    /// </summary>
    private static void RegisterAuthentication(
        IServiceCollection services,
        IConfiguration? configuration)
    {
        var serviceProvider = services.BuildServiceProvider();
        var jwtSettings = serviceProvider.GetService<IOptions<JwtSettings>>()?.Value;
        var pawthorizeOptions = serviceProvider.GetService<IOptions<PawthorizeOptions>>()?.Value;

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

        // Configure cookie policy if using cookies
        if (pawthorizeOptions?.TokenDelivery == TokenDeliveryStrategy.HttpOnlyCookies ||
            pawthorizeOptions?.TokenDelivery == TokenDeliveryStrategy.Hybrid)
        {
            services.AddHttpContextAccessor();
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
                    OnMessageReceived = context =>
                    {
                        // Try to read token from Authorization header first (default behavior)
                        // If not found and using HttpOnlyCookies mode, try to read from cookie
                        var tokenDelivery = pawthorizeOptions?.TokenDelivery ?? TokenDeliveryStrategy.Hybrid;

                        // Only read from cookie if:
                        // 1. Using HttpOnlyCookies mode (access token is in cookie)
                        // 2. No Authorization header is present (allow header to override cookie)
                        if (tokenDelivery == TokenDeliveryStrategy.HttpOnlyCookies)
                        {
                            if (string.IsNullOrEmpty(context.Token))
                            {
                                var accessToken = context.Request.Cookies["access_token"];
                                if (!string.IsNullOrEmpty(accessToken))
                                {
                                    context.Token = accessToken;
                                }
                            }
                        }

                        return Task.CompletedTask;
                    },
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
        services.AddScoped<CsrfTokenService>();
        services.AddScoped<PasswordValidationService>();
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

    /// <summary>
    /// Internal method to register OAuth services based on options configuration.
    /// </summary>
    private static void RegisterOAuth<TUser>(
        IServiceCollection services,
        PawthorizeResponseOptions options)
        where TUser : class, IAuthenticatedUser
    {
        // Register OAuth configuration
        if (options.Configuration != null)
        {
            services.Configure<Configuration.OAuthOptions>(
                options.Configuration.GetSection(Configuration.OAuthOptions.SectionName));
        }

        // Register HTTP client factory for OAuth providers
        services.AddHttpClient();

        // Use internal state token repository if not already registered
        // Users can override by registering their own IStateTokenRepository<TStateToken> before calling AddPawthorize
        services.TryAddSingleton<IStateTokenRepository<Models.InternalStateToken>, Repositories.InternalStateTokenRepository>();

        // Register OAuth provider factory with all registered providers
        services.AddSingleton<IOAuthProviderFactory>(sp =>
        {
            var factory = new Services.OAuthProviderFactory(
                sp,
                sp.GetRequiredService<ILogger<Services.OAuthProviderFactory>>());

            // Register all providers from options
            foreach (var providerReg in options.OAuthProviders)
            {
                var registerMethod = factory.GetType()
                    .GetMethod(nameof(Services.OAuthProviderFactory.RegisterProvider))!
                    .MakeGenericMethod(providerReg.ProviderType);

                registerMethod.Invoke(factory, new object[] { providerReg.ProviderName });
            }

            return factory;
        });

        // Register state token service
        services.AddScoped<IStateTokenService, Services.StateTokenService<Models.InternalStateToken>>();

        // Register external authentication service
        services.AddScoped<Services.ExternalAuthenticationService<TUser>>();

        // Register OAuth provider instances
        foreach (var providerReg in options.OAuthProviders)
        {
            services.AddTransient(providerReg.ProviderType);
        }

        // Register OAuth handlers
        services.AddScoped<Handlers.OAuthInitiateHandler>();
        services.AddScoped<Handlers.OAuthCallbackHandler<TUser>>();
        services.AddScoped<Handlers.LinkProviderHandler<TUser>>();
        services.AddScoped<Handlers.UnlinkProviderHandler<TUser>>();
        services.AddScoped<Handlers.ListLinkedProvidersHandler<TUser>>();
    }

    /// <summary>
    /// Register rate limiting services.
    /// </summary>
    private static void RegisterRateLimiting(
        IServiceCollection services,
        IConfiguration? configuration)
    {
        // Build a temporary service provider to get the options
        var serviceProvider = services.BuildServiceProvider();

        try
        {
            var pawthorizeOptions = serviceProvider.GetService<IOptions<PawthorizeOptions>>()?.Value;
            var rateLimitingOptions = pawthorizeOptions?.RateLimiting ?? new Configuration.PawthorizeRateLimitingOptions();

            var logger = serviceProvider.GetService<ILogger<RateLimitingService>>();
            var rateLimitingService = new RateLimitingService(logger);

            // Validate configuration first
            rateLimitingService.ValidateConfiguration(rateLimitingOptions);

            // Configure rate limiting
            rateLimitingService.ConfigureRateLimiting(services, rateLimitingOptions);

            // Store rate limiting enabled state in metadata for WebApplicationExtensions
            var metadata = serviceProvider.GetService<PawthorizeTypeMetadata>();
            if (metadata != null)
            {
                // Use reflection to set the rate limiting enabled state
                var field = typeof(PawthorizeTypeMetadata).GetField("_rateLimitingEnabled",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                field?.SetValue(metadata, rateLimitingOptions.Enabled);
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
