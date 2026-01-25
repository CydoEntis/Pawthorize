using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Internal;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.Endpoints.Sessions;

/// <summary>
/// Handler for revoking a specific session (refresh token) by its session ID.
/// This allows users to logout a specific device/session while keeping others active.
/// </summary>
public class RevokeSessionHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IValidator<RevokeSessionRequest> _validator;
    private readonly ILogger<RevokeSessionHandler<TUser>> _logger;

    public RevokeSessionHandler(
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<RevokeSessionRequest> validator,
        ILogger<RevokeSessionHandler<TUser>> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Revoke a specific session (refresh token) by its session ID for the authenticated user.
    /// </summary>
    public async Task<IResult> HandleAsync(
        RevokeSessionRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        // Check if user is authenticated first
        if (!httpContext.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("Revoke session failed: User is not authenticated");
            return Results.Unauthorized();
        }

        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Revoke session failed: UserId claim not found in token");
            return Results.Unauthorized();
        }

        _logger.LogInformation("Revoking session {SessionId} for UserId: {UserId}", request.SessionId, userId);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Revoke session request validation passed");

            // Verify that the session belongs to the current user before revoking
            var tokenInfo = await _refreshTokenRepository.ValidateAsync(request.SessionId, cancellationToken);

            if (tokenInfo == null)
            {
                _logger.LogWarning("Revoke session failed: Session {SessionId} not found", request.SessionId);
                return Results.NotFound(new { message = "Session not found." });
            }

            if (tokenInfo.UserId != userId)
            {
                _logger.LogWarning("Revoke session failed: Session {SessionId} does not belong to UserId: {UserId}",
                    request.SessionId, userId);
                return Results.Forbid();
            }

            await _refreshTokenRepository.RevokeAsync(request.SessionId, cancellationToken);

            _logger.LogInformation("Session {SessionId} revoked successfully for UserId: {UserId}",
                request.SessionId, userId);

            var response = new
            {
                message = "Session revoked successfully."
            };

            return response.Ok(httpContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error revoking session {SessionId} for UserId: {UserId}",
                request.SessionId, userId);
            throw;
        }
    }
}
