using Pawthorize.Abstractions;
using Pawthorize.Extensions;
using Pawthorize.Endpoints.Register;
using Pawthorize.Services;
using Pawthorize.Sample.MinimalApi.Factories;
using Pawthorize.Sample.MinimalApi.Models;
using Pawthorize.Sample.MinimalApi.Repositories;
using Pawthorize.Sample.MinimalApi.Services;
using Pawthorize.Templates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();
    options.AddGoogle();
    options.AddDiscord();
    options.AddGitHub();
});

// Register repository implementations (in production, use database-backed repositories)
builder.Services.AddSingleton<IUserRepository<User>, InMemoryUserRepository>();
builder.Services.AddSingleton<IRefreshTokenRepository, InMemoryRefreshTokenRepository>();
builder.Services.AddSingleton<ITokenRepository, InMemoryTokenRepository>();

// Register email services
builder.Services.AddSingleton<IEmailSender, InMemoryEmailSender>();
builder.Services.AddSingleton<IEmailTemplateProvider, DefaultEmailTemplateProvider>();

// Register email verification service
builder.Services.AddScoped<IEmailVerificationService, EmailVerificationService>();

// Register user factory for creating user entities from registration requests
builder.Services.AddScoped<IUserFactory<User, RegisterRequest>, UserFactory>();

// Register OAuth repository (in production, use database-backed repository)
// Note: State token storage is handled internally by default
builder.Services.AddSingleton<IExternalAuthRepository<User>, InMemoryExternalAuthRepository>();

var app = builder.Build();

app.UsePawthorize();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Map all authentication endpoints (OAuth endpoints auto-detected and mapped)
app.MapPawthorize();

// Example: Custom endpoint with Pawthorize rate limiting
// This demonstrates how to apply Pawthorize's rate limiting policies to your own endpoints
app.MapPost("/api/custom/verify-otp", (string otp) => new
{
    Message = "OTP verification endpoint",
    Note = "This endpoint uses Pawthorize's strict Login rate limit (5 req/5min)"
})
.RequirePawthorizeRateLimit(PawthorizeRateLimitPolicy.Login)
.WithTags("Custom Endpoints")
.WithOpenApi();

// Example: Custom endpoint group with rate limiting
var customAuthGroup = app.MapGroup("/api/custom-auth")
    .WithTags("Custom Auth Group")
    .RequirePawthorizeRateLimit(PawthorizeRateLimitPolicy.Register);

customAuthGroup.MapPost("/verify-phone", (string phone) => new
{
    Message = "Phone verification endpoint",
    Note = "Entire group uses Register rate limit (3 req/15min)"
})
.WithOpenApi();

customAuthGroup.MapPost("/send-verification", (string phone) => new
{
    Message = "Send verification code endpoint",
    Note = "Entire group uses Register rate limit (3 req/15min)"
})
.WithOpenApi();

app.MapGet("/", () => new
{
    Message = "Pawthorize Sample API - Authentication with OAuth 2.0",
    Version = "1.0.0",
    Documentation = "/swagger",
    Endpoints = new
    {
        Authentication = new[]
        {
            "POST /api/auth/register - Register new user",
            "POST /api/auth/login - Login with email/password",
            "POST /api/auth/refresh - Refresh access token",
            "POST /api/auth/logout - Logout (revoke refresh token)",
            "POST /api/auth/forgot-password - Request password reset",
            "POST /api/auth/reset-password - Reset password with token",
            "POST /api/auth/change-password - Change password (requires auth)",
            "GET  /api/auth/me - Get current user info (requires auth)",
            "GET  /api/auth/sessions - Get active sessions (requires auth)",
            "POST /api/auth/sessions/revoke-others - Revoke other sessions (requires auth)"
        },
        OAuth = new[]
        {
            "GET    /api/auth/oauth/{provider} - Initiate OAuth flow (google, discord, github)",
            "GET    /api/auth/oauth/{provider}/callback - OAuth callback handler",
            "POST   /api/auth/oauth/{provider}/link - Link OAuth provider (requires auth)",
            "DELETE /api/auth/oauth/{provider}/unlink - Unlink OAuth provider (requires auth)",
            "GET    /api/auth/oauth/linked - List linked OAuth providers (requires auth)"
        }
    },
    Note = "OAuth requires configuration in appsettings.json. See README for setup instructions."
});

app.Run();
