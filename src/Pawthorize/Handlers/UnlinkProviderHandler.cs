using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Handlers;

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
    /// Handle unlink provider request.
    /// </summary>
    /// <param name="provider">Provider name</param>
    /// <param name="context">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        string provider,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Unlinking provider {Provider} from authenticated user", provider);

        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Unlink provider attempt without authentication");
            throw new InvalidCredentialsError("You must be logged in to unlink a provider");
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
}
