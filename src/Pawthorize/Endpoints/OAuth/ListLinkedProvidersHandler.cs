using System.Security.Claims;
using ErrorHound.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.OAuth;

/// <summary>
/// Handler for listing all linked OAuth providers for an authenticated user.
/// </summary>
public class ListLinkedProvidersHandler<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly ExternalAuthenticationService<TUser> _externalAuthService;
    private readonly ILogger<ListLinkedProvidersHandler<TUser>> _logger;

    public ListLinkedProvidersHandler(
        ExternalAuthenticationService<TUser> externalAuthService,
        ILogger<ListLinkedProvidersHandler<TUser>> logger)
    {
        _externalAuthService = externalAuthService;
        _logger = logger;
    }

    /// <summary>
    /// Returns all OAuth providers currently linked to the authenticated user's account.
    /// </summary>
    /// <param name="context">HTTP context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="NotAuthenticatedError">User is not authenticated.</exception>
    public async Task<IResult> HandleAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Fetching linked providers for authenticated user");

        try
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("List providers attempt without authentication");
                throw new NotAuthenticatedError();
            }

            var linkedProviders = await _externalAuthService.GetLinkedProvidersAsync(
                userId, cancellationToken);

            var providerList = linkedProviders.Select(p => new
            {
                provider = p.Provider,
                email = p.ProviderEmail,
                username = p.ProviderUsername,
                linkedAt = p.LinkedAt
            });

            _logger.LogInformation("Retrieved {Count} linked providers for user {UserId}",
                providerList.Count(), userId);

            return Results.Ok(new
            {
                providers = providerList
            });
        }
        catch (Exception ex) when (ex is not ApiError)
        {
            _logger.LogError(ex, "Unexpected error while listing linked providers");
            throw;
        }
    }
}
