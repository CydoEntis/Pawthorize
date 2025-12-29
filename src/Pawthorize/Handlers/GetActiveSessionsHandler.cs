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
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Get active sessions failed: UserId claim not found in token");
            return Results.Unauthorized();
        }

        _logger.LogInformation("Retrieving active sessions for UserId: {UserId}", userId);

        try
        {
            var tokens = await _refreshTokenRepository.GetAllActiveAsync(userId, cancellationToken);

            _logger.LogInformation("Retrieved {Count} active sessions for UserId: {UserId}",
                tokens.Count(), userId);

            var response = tokens.Select(t => new
            {
                t.UserId,
                t.CreatedAt,
                t.ExpiresAt,
                t.IsExpired
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
