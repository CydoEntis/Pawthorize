using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Extensions;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;
using Pawthorize.Core.Services;
using Pawthorize.Core.Templates;
using Pawthorize.Sample.MinimalApi.Factories;
using Pawthorize.Sample.MinimalApi.Models;
using Pawthorize.Sample.MinimalApi.Repositories;
using Pawthorize.Sample.MinimalApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure JWT settings from appsettings
var jwtSettings = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()
    ?? throw new InvalidOperationException("JWT settings are not configured in appsettings.json");

// Add authentication with JWT Bearer
builder.Services.AddAuthentication(options =>
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
});

builder.Services.AddAuthorization();

builder.Services.AddPawthorize<User, RegisterRequest>(
    builder.Configuration,
    options =>
    {
        options.UseDefaultFormatters();
    });

// Register repositories
builder.Services.AddSingleton<IUserRepository<User>, InMemoryUserRepository>();
builder.Services.AddSingleton<IRefreshTokenRepository, InMemoryRefreshTokenRepository>();
builder.Services.AddSingleton<ITokenRepository, InMemoryTokenRepository>();

// Register email services
builder.Services.AddSingleton<IEmailSender, InMemoryEmailSender>();
builder.Services.AddSingleton<IEmailTemplateProvider, DefaultEmailTemplateProvider>();

// Register email verification service
builder.Services.AddScoped<IEmailVerificationService, EmailVerificationService>();

// Register user factory
builder.Services.AddScoped<IUserFactory<User, RegisterRequest>, UserFactory>();

var app = builder.Build();

// Add Pawthorize middleware for error handling
app.UsePawthorize();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPawthorizeEndpoints<User, RegisterRequest>();

app.MapGet("/", () => new
{
    Message = "Pawthorize Sample API - MVP 1.0",
    Version = "1.0.0",
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