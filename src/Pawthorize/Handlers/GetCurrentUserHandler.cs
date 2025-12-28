using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Core.Abstractions;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for retrieving the current authenticated user's information.
/// </summary>
public class GetCurrentUserHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly ILogger<GetCurrentUserHandler<TUser>> _logger;

    public GetCurrentUserHandler(
        IUserRepository<TUser> userRepository,
        ILogger<GetCurrentUserHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _logger = logger;
    }

    /// <summary>
    /// Get current authenticated user's information.
    /// </summary>
    public async Task<IResult> HandleAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Get current user failed: UserId claim not found in token");
            return Results.Unauthorized();
        }

        _logger.LogInformation("Retrieving current user information for UserId: {UserId}", userId);

        try
        {
            var user = await _userRepository.FindByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                _logger.LogWarning("Get current user failed: User not found for UserId: {UserId}", userId);
                return Results.Unauthorized();
            }

            _logger.LogInformation("Current user information retrieved successfully for UserId: {UserId}", userId);

            var response = new
            {
                Id = user.Id,
                Email = user.Email,
                Name = user.Name,
                Roles = user.Roles,
                IsEmailVerified = user.IsEmailVerified,
                AdditionalClaims = user.AdditionalClaims
            };

            return response.Ok(httpContext);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error retrieving current user for UserId: {UserId}", userId);
            throw;
        }
    }
}
