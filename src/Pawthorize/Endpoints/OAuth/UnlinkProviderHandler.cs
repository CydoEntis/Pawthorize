using System.Security.Claims;
using ErrorHound.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.OAuth;

/// <summary>
/// Handler for unlinking an OAuth provider from an authenticated user.
/// </summary>
public class UnlinkProviderHandler<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly ExternalAuthenticationService<TUser> _externalAuthService;
    private readonly ILogger<UnlinkProviderHandler<TUser>> _logger;

    public UnlinkProviderHandler(
        ExternalAuthenticationService<TUser> externalAuthService,
        ILogger<UnlinkProviderHandler<TUser>> logger)
    {
        _externalAuthService = externalAuthService;
        _logger = logger;
    }

    /// <summary>
    /// Removes the specified OAuth provider link from the authenticated user's account.
    /// </summary>
    /// <param name="provider">OAuth provider name (e.g. "google", "discord").</param>
    /// <param name="context">HTTP context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="NotAuthenticatedError">User is not authenticated.</exception>
    /// <exception cref="OAuthAccountLinkingError">Cannot unlink the last authentication method.</exception>
    public async Task<IResult> HandleAsync(
        string provider,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Unlinking provider {Provider} from authenticated user", provider);

        try
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Unlink provider attempt without authentication");
                throw new NotAuthenticatedError();
            }

            await _externalAuthService.UnlinkProviderAsync(userId, provider, cancellationToken);

            _logger.LogInformation("Successfully unlinked provider {Provider} from user {UserId}",
                provider, userId);

            return Results.Ok(new
            {
                success = true,
                provider
            });
        }
        catch (OAuthAccountLinkingError)
        {
            _logger.LogWarning("Unlink provider failed for provider {Provider}: linking constraint violation", provider);
            throw;
        }
        catch (Exception ex) when (ex is not ApiError)
        {
            _logger.LogError(ex, "Unexpected error during unlink provider {Provider}", provider);
            throw;
        }
    }
}
