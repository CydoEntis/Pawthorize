using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for retrieving all active sessions (refresh tokens) for the current user.
/// </summary>
public class GetActiveSessionsHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly ILogger<GetActiveSessionsHandler<TUser>> _logger;

    public GetActiveSessionsHandler(
        IRefreshTokenRepository refreshTokenRepository,
        ILogger<GetActiveSessionsHandler<TUser>> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _logger = logger;
    }

    /// <summary>
    /// Get all active refresh tokens (sessions) for the current user.
    /// </summary>
    public async Task<IResult> HandleAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        // Check if user is authenticated first
        if (!httpContext.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("Get active sessions failed: User is not authenticated. " +
                "This usually means JWT Bearer authentication middleware is not configured or the token is invalid.");
            return Results.Unauthorized();
        }

        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            var allClaims = string.Join(", ", httpContext.User.Claims.Select(c => $"{c.Type}={c.Value}"));
            _logger.LogWarning("Get active sessions failed: UserId claim ({ClaimType}) not found in token. " +
                "Available claims: {Claims}. " +
                "Make sure your JWT token includes a '{ClaimType}' claim with the user's ID.",
                ClaimTypes.NameIdentifier, allClaims, ClaimTypes.NameIdentifier);
            return Results.Unauthorized();
        }

        _logger.LogInformation("Retrieving active sessions for UserId: {UserId}", userId);

        try
        {
            var tokens = await _refreshTokenRepository.GetAllActiveAsync(userId, cancellationToken);

            _logger.LogInformation("Retrieved {Count} active sessions for UserId: {UserId}",
                tokens.Count(), userId);

            // Get current session token hash if present in request
            string? currentTokenHash = null;
            var refreshTokenCookie = httpContext.Request.Cookies["refresh_token"];
            if (!string.IsNullOrEmpty(refreshTokenCookie))
            {
                currentTokenHash = Utilities.TokenHasher.HashToken(refreshTokenCookie);
            }

            var response = tokens.Select(t => new
            {
                SessionId = t.TokenHash,
                t.UserId,
                t.CreatedAt,
                t.ExpiresAt,
                t.IsExpired,
                DeviceInfo = t.DeviceInfo ?? "Unknown",
                IpAddress = t.IpAddress ?? "Unknown",
                LastActivityAt = t.LastActivityAt,
                IsCurrentSession = !string.IsNullOrEmpty(currentTokenHash) && t.TokenHash == currentTokenHash
            }).ToList();

            return response.Ok(httpContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error retrieving active sessions for UserId: {UserId}", userId);
            throw;
        }
    }
}
