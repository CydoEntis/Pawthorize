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
using Pawthorize.Configuration;
using ChangeEmail = Pawthorize.Endpoints.ChangeEmail;
using ChangePassword = Pawthorize.Endpoints.ChangePassword;
using ForgotPassword = Pawthorize.Endpoints.ForgotPassword;
using Login = Pawthorize.Endpoints.Login;
using Logout = Pawthorize.Endpoints.Logout;
using OAuth = Pawthorize.Endpoints.OAuth;
using Refresh = Pawthorize.Endpoints.Refresh;
using Repositories = Pawthorize.Services.OAuth.Repositories;
using Register = Pawthorize.Endpoints.Register;
using ResetPassword = Pawthorize.Endpoints.ResetPassword;
using Sessions = Pawthorize.Endpoints.Sessions;
using SetPassword = Pawthorize.Endpoints.SetPassword;
using User = Pawthorize.Endpoints.User;
using VerifyEmail = Pawthorize.Endpoints.VerifyEmail;
using Pawthorize.Internal;
using Pawthorize.Middleware;
using Pawthorize.Services.OAuth.Models;
using Pawthorize.Services;
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
        return AddPawthorize<TUser, Register.RegisterRequest>(services, configure);
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
        where TRegisterRequest : Register.RegisterRequest
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
                        var logger = context.HttpContext.RequestServices.GetService<ILogger<JwtBearerEvents>>();

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
                                    logger?.LogDebug("[Pawthorize JWT] Token retrieved from access_token cookie");
                                }
                                else
                                {
                                    logger?.LogWarning("[Pawthorize JWT] No token found in Authorization header or access_token cookie");
                                }
                            }
                        }
                        else
                        {
                            if (string.IsNullOrEmpty(context.Token))
                            {
                                logger?.LogWarning("[Pawthorize JWT] No Authorization header found in request to {Path}", context.Request.Path);
                            }
                            else
                            {
                                logger?.LogDebug("[Pawthorize JWT] Token retrieved from Authorization header");
                            }
                        }

                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetService<ILogger<JwtBearerEvents>>();
                        var env = context.HttpContext.RequestServices.GetService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
                        var isDevelopment = env?.EnvironmentName == "Development";

                        var exceptionType = context.Exception.GetType().Name;
                        var exceptionMessage = context.Exception.Message;

                        // Log detailed error information
                        logger?.LogError(context.Exception,
                            "[Pawthorize JWT] Authentication failed for {Path}. Exception: {ExceptionType}, Message: {Message}",
                            context.Request.Path, exceptionType, exceptionMessage);

                        // Store detailed error information in HttpContext items for development environments
                        if (isDevelopment)
                        {
                            context.HttpContext.Items["Pawthorize.JwtError"] = new
                            {
                                ExceptionType = exceptionType,
                                Message = exceptionMessage,
                                InnerException = context.Exception.InnerException?.Message,
                                TokenSource = context.Request.Headers.ContainsKey("Authorization") ? "Header" : "Cookie",
                                Path = context.Request.Path.ToString(),
                                Method = context.Request.Method
                            };
                        }

                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetService<ILogger<JwtBearerEvents>>();
                        var userId = context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

                        logger?.LogDebug("[Pawthorize JWT] Token validated successfully for UserId: {UserId} on {Path}",
                            userId ?? "Unknown", context.Request.Path);

                        return Task.CompletedTask;
                    },
                    OnChallenge = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetService<ILogger<JwtBearerEvents>>();
                        var env = context.HttpContext.RequestServices.GetService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
                        var isDevelopment = env?.EnvironmentName == "Development";

                        context.HandleResponse();

                        // Get detailed error information
                        var errorDetails = context.HttpContext.Items["Pawthorize.JwtError"] as dynamic;
                        string errorMessage;

                        if (isDevelopment && errorDetails != null)
                        {
                            // Provide detailed error message in development
                            var exceptionType = errorDetails.ExceptionType?.ToString() ?? "Unknown";
                            var message = errorDetails.Message?.ToString() ?? "Unknown error";

                            errorMessage = exceptionType switch
                            {
                                "SecurityTokenExpiredException" =>
                                    $"JWT token has expired. Please refresh your token or login again. Details: {message}",

                                "SecurityTokenInvalidSignatureException" =>
                                    "JWT signature validation failed. This usually means:\n" +
                                    "1. The JWT Secret in appsettings.json doesn't match the one used to generate the token\n" +
                                    "2. The token was tampered with\n" +
                                    $"Details: {message}",

                                "SecurityTokenInvalidIssuerException" =>
                                    $"JWT Issuer validation failed. The 'iss' claim in the token doesn't match the 'Jwt:Issuer' setting in appsettings.json. Details: {message}",

                                "SecurityTokenInvalidAudienceException" =>
                                    $"JWT Audience validation failed. The 'aud' claim in the token doesn't match the 'Jwt:Audience' setting in appsettings.json. Details: {message}",

                                "SecurityTokenNotYetValidException" =>
                                    $"JWT token is not yet valid (nbf claim is in the future). Check system clock synchronization. Details: {message}",

                                "SecurityTokenNoExpirationException" =>
                                    $"JWT token has no expiration claim. All tokens must have an 'exp' claim. Details: {message}",

                                "SecurityTokenInvalidLifetimeException" =>
                                    $"JWT token lifetime is invalid. Check that 'nbf' is before 'exp' and both are valid timestamps. Details: {message}",

                                _ when string.IsNullOrEmpty(context.Error) && errorDetails == null =>
                                    "Authentication required. No valid JWT token found in the Authorization header or cookies.",

                                _ =>
                                    $"JWT authentication failed: {exceptionType}\n" +
                                    $"Message: {message}\n" +
                                    $"Token Source: {errorDetails.TokenSource}\n" +
                                    $"Path: {errorDetails.Path}"
                            };

                            logger?.LogWarning("[Pawthorize JWT] Challenge triggered: {ErrorMessage}", errorMessage);
                        }
                        else
                        {
                            // Generic error message in production
                            errorMessage = string.IsNullOrEmpty(context.Error)
                                ? "Authentication required"
                                : "Invalid or expired token";

                            logger?.LogWarning("[Pawthorize JWT] Authentication challenge for {Path}: {Error}",
                                context.Request.Path, context.Error ?? "No token provided");
                        }

                        throw new UnauthorizedError(errorMessage);
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
        services.AddScoped<IPasswordHasher, Services.PasswordHasher>();
        services.AddScoped<Services.JwtService<TUser>>();
        services.AddScoped<Services.AuthenticationService<TUser>>();
        services.AddScoped<IPasswordResetService, Services.PasswordResetService>();
        services.AddScoped<IEmailChangeService, Services.EmailChangeService>();
        services.AddScoped<IEmailVerificationService, Services.EmailVerificationService>();
        services.AddScoped<Services.CsrfTokenService>();
        services.AddScoped<Services.PasswordValidationService>();
    }

    /// <summary>
    /// Register all authentication handlers.
    /// </summary>
    private static void RegisterHandlers<TUser, TRegisterRequest>(IServiceCollection services)
        where TUser : class, IAuthenticatedUser
        where TRegisterRequest : Register.RegisterRequest
    {
        services.AddScoped<Login.LoginHandler<TUser>>();
        services.AddScoped<Register.RegisterHandler<TUser, TRegisterRequest>>();
        services.AddScoped<Refresh.RefreshHandler<TUser>>();
        services.AddScoped<Logout.LogoutHandler<TUser>>();
        services.AddScoped<ForgotPassword.ForgotPasswordHandler<TUser>>();
        services.AddScoped<ResetPassword.ResetPasswordHandler<TUser>>();
        services.AddScoped<ChangePassword.ChangePasswordHandler<TUser>>();
        services.AddScoped<SetPassword.SetPasswordHandler<TUser>>();
        services.AddScoped<VerifyEmail.VerifyEmailHandler<TUser>>();
        services.AddScoped<ChangeEmail.ChangeEmailHandler<TUser>>();
        services.AddScoped<ChangeEmail.VerifyEmailChangeHandler<TUser>>();
        services.AddScoped<User.GetCurrentUserHandler<TUser>>();
        services.AddScoped<Sessions.GetActiveSessionsHandler<TUser>>();
        services.AddScoped<Sessions.RevokeAllOtherSessionsHandler<TUser>>();
        services.AddScoped<Sessions.RevokeSessionHandler<TUser>>();
    }

    /// <summary>
    /// Register FluentValidation validators.
    /// </summary>
    private static void RegisterValidators<TRegisterRequest>(IServiceCollection services)
        where TRegisterRequest : Register.RegisterRequest
    {
        services.AddScoped<IValidator<Login.LoginRequest>, Login.LoginRequestValidator>();
        services.AddScoped<IValidator<Refresh.RefreshTokenRequest>, Refresh.RefreshTokenRequestValidator>();
        services.AddScoped<IValidator<Logout.LogoutRequest>, Logout.LogoutRequestValidator>();
        services.AddScoped<IValidator<Register.RegisterRequest>, Register.RegisterRequestValidator>();
        services.AddScoped<IValidator<ForgotPassword.ForgotPasswordRequest>, ForgotPassword.ForgotPasswordRequestValidator>();
        services.AddScoped<IValidator<ResetPassword.ResetPasswordRequest>, ResetPassword.ResetPasswordRequestValidator>();
        services.AddScoped<IValidator<ChangePassword.ChangePasswordRequest>, ChangePassword.ChangePasswordRequestValidator>();
        services.AddScoped<IValidator<SetPassword.SetPasswordRequest>, SetPassword.SetPasswordRequestValidator>();
        services.AddScoped<IValidator<VerifyEmail.VerifyEmailRequest>, VerifyEmail.VerifyEmailRequestValidator>();
        services.AddScoped<IValidator<ChangeEmail.ChangeEmailRequest>, ChangeEmail.ChangeEmailRequestValidator>();
        services.AddScoped<IValidator<Sessions.RevokeAllOtherSessionsRequest>, Sessions.RevokeAllOtherSessionsRequestValidator>();
        services.AddScoped<IValidator<Sessions.RevokeSessionRequest>, Sessions.RevokeSessionRequestValidator>();


        if (typeof(TRegisterRequest) != typeof(Register.RegisterRequest))
        {
            services.AddScoped(typeof(IValidator<TRegisterRequest>), serviceProvider =>
            {
                var existingValidator = serviceProvider.GetService<IValidator<TRegisterRequest>>();
                if (existingValidator != null)
                    return existingValidator;

                return serviceProvider.GetRequiredService<IValidator<Register.RegisterRequest>>();
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
    /// Configure SuccessHound 2.0 with optional custom formatter.
    /// </summary>
    private static void ConfigureSuccessHound(IServiceCollection services, Type? formatterType)
    {
        var targetFormatterType = formatterType;

        // Default to SuccessHound 2.0's DefaultSuccessFormatter if none specified
        if (targetFormatterType == null)
        {
            targetFormatterType = Type.GetType("SuccessHound.Defaults.DefaultSuccessFormatter, SuccessHound");
            
            if (targetFormatterType == null)
            {
                throw new InvalidOperationException(
                    "Could not find SuccessHound's DefaultSuccessFormatter. " +
                    "Please specify a custom formatter using options.UseSuccessFormatter<T>(). " +
                    "Make sure SuccessHound 2.0 package is installed.");
            }
        }

        // Get AddSuccessHound method from SuccessHound.Extensions
        var addSuccessHoundMethod = typeof(SuccessHound.Extensions.SuccessHoundExtensions)
            .GetMethods()
            .FirstOrDefault(m => m.Name == "AddSuccessHound" && 
                                 m.GetParameters().Length == 2 &&
                                 m.GetParameters()[0].ParameterType == typeof(IServiceCollection));

        if (addSuccessHoundMethod == null)
        {
            throw new InvalidOperationException(
                "Could not find SuccessHound's AddSuccessHound method. " +
                "Please ensure SuccessHound 2.0 is properly installed.");
        }

        // Get the options type (Action<SuccessHoundOptions>)
        var optionsActionType = addSuccessHoundMethod.GetParameters()[1].ParameterType;
        var optionsType = optionsActionType.GetGenericArguments()[0];

        // Get UseFormatter<T>() method
        var useFormatterMethod = optionsType
            .GetMethods()
            .FirstOrDefault(m => m.Name == "UseFormatter" && 
                                 m.IsGenericMethod && 
                                 m.GetGenericArguments().Length == 1);

        if (useFormatterMethod == null)
        {
            throw new InvalidOperationException(
                "Could not find SuccessHound's UseFormatter method. " +
                "Please ensure SuccessHound 2.0 is properly installed.");
        }

        // Create Action<SuccessHoundOptions> that calls options.UseFormatter<T>()
        var optionsParam = System.Linq.Expressions.Expression.Parameter(optionsType, "options");
        var genericUseFormatter = useFormatterMethod.MakeGenericMethod(targetFormatterType);
        var callExpression = System.Linq.Expressions.Expression.Call(optionsParam, genericUseFormatter);
        var lambda = System.Linq.Expressions.Expression.Lambda(optionsActionType, callExpression, optionsParam);
        var configAction = lambda.Compile();

        // Invoke AddSuccessHound(services, configAction)
        addSuccessHoundMethod.Invoke(null, new object[] { services, configAction });
    }

    /// <summary>
    /// Configure ErrorHound with optional custom formatter.
    /// </summary>
    private static void ConfigureErrorHound(IServiceCollection services, Type? formatterType)
    {
        var targetFormatterType = formatterType;

        if (targetFormatterType == null)
        {
            // Use Pawthorize's custom formatter as the default
            // This ensures ValidationError field errors are properly serialized
            targetFormatterType = typeof(Formatters.PawthorizeErrorFormatter);
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

            // Normalize provider dictionary keys to lowercase to ensure case-insensitive lookup
            services.PostConfigure<Configuration.OAuthOptions>(opts =>
            {
                var normalizedProviders = new Dictionary<string, Configuration.OAuthProviderConfig>(
                    StringComparer.OrdinalIgnoreCase);

                foreach (var kvp in opts.Providers)
                {
                    normalizedProviders[kvp.Key.ToLowerInvariant()] = kvp.Value;
                }

                opts.Providers = normalizedProviders;
            });
        }

        // Register HTTP client factory for OAuth providers
        services.AddHttpClient();

        // Use internal state token repository if not already registered
        // Users can override by registering their own IStateTokenRepository<TStateToken> before calling AddPawthorize
        services.TryAddSingleton<IStateTokenRepository<InternalStateToken>, Repositories.InternalStateTokenRepository>();

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
        services.AddScoped<IStateTokenService, Services.StateTokenService<InternalStateToken>>();

        // Register external authentication service
        services.AddScoped<Services.ExternalAuthenticationService<TUser>>();

        // Register OAuth provider instances
        foreach (var providerReg in options.OAuthProviders)
        {
            services.AddTransient(providerReg.ProviderType);
        }

        // Register OAuth handlers
        services.AddScoped<OAuth.OAuthInitiateHandler>();
        services.AddScoped<OAuth.OAuthCallbackHandler<TUser>>();
        services.AddScoped<OAuth.LinkProviderHandler<TUser>>();
        services.AddScoped<OAuth.UnlinkProviderHandler<TUser>>();
        services.AddScoped<OAuth.ListLinkedProvidersHandler<TUser>>();
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
