using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Extensions;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Services;
using Pawthorize.Core.Templates;
using Pawthorize.Sample.MinimalApi.Factories;
using Pawthorize.Sample.MinimalApi.Models;
using Pawthorize.Sample.MinimalApi.Repositories;
using Pawthorize.Sample.MinimalApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add Pawthorize - handles JWT authentication, ErrorHound integration, and all auth endpoints
// This single call configures:
// - JWT Bearer authentication with automatic OnChallenge handling
// - ErrorHound for consistent error responses
// - SuccessHound for consistent success responses
// - All authentication endpoints (login, register, refresh, etc.)
builder.Services.AddPawthorize<User, RegisterRequest>(
    builder.Configuration,
    options =>
    {
        options.UseDefaultFormatters();
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

var app = builder.Build();

// Add Pawthorize middleware - handles all error responses consistently via ErrorHound
app.UsePawthorize();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPawthorizeEndpoints<User, RegisterRequest>();

app.MapGet("/", () => new
{
    Message = "Pawthorize Sample API",
    Version = "0.1.0",
    Endpoints = new[]
    {
        "POST /api/auth/register - Register new user",
        "POST /api/auth/login - Login with email/password",
        "POST /api/auth/refresh - Refresh access token",
        "POST /api/auth/logout - Logout (revoke refresh token)",
        "POST /api/auth/forgot-password - Request password reset",
        "POST /api/auth/reset-password - Reset password with token",
        "POST /api/auth/change-password - Change password (requires auth)",
        "GET /swagger - API documentation"
    }
});

app.Run();