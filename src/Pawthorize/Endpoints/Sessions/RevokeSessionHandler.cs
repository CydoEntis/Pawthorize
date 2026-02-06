using ErrorHound.Core;
using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
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
    /// Revokes a specific session by ID after verifying it belongs to the authenticated user.
    /// </summary>
    /// <exception cref="NotAuthenticatedError">User is not authenticated or UserId claim is missing.</exception>
    /// <exception cref="SessionNotFoundError">No session exists for the given ID.</exception>
    /// <exception cref="SessionForbiddenError">Session belongs to a different user.</exception>
    public async Task<IResult> HandleAsync(
        RevokeSessionRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        if (!httpContext.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning("Revoke session failed: User is not authenticated");
            throw new NotAuthenticatedError();
        }

        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Revoke session failed: UserId claim not found in token");
            throw new NotAuthenticatedError();
        }

        _logger.LogInformation("Revoking session {SessionId} for UserId: {UserId}", request.SessionId, userId);

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Revoke session request validation passed");

            var tokenInfo = await _refreshTokenRepository.ValidateAsync(request.SessionId, cancellationToken);

            if (tokenInfo == null)
            {
                _logger.LogWarning("Revoke session failed: Session {SessionId} not found", request.SessionId);
                throw new SessionNotFoundError();
            }

            if (tokenInfo.UserId != userId)
            {
                _logger.LogWarning("Revoke session failed: Session {SessionId} does not belong to UserId: {UserId}",
                    request.SessionId, userId);
                throw new SessionForbiddenError();
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
        catch (Exception ex) when (ex is not ApiError)
        {
            _logger.LogError(ex, "Unexpected error revoking session {SessionId} for UserId: {UserId}",
                request.SessionId, userId);
            throw;
        }
    }
}
