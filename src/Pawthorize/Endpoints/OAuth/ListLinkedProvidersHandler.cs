using System.Security.Claims;
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
    /// Handle list linked providers request.
    /// </summary>
    /// <param name="context">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Fetching linked providers for authenticated user");

        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("List providers attempt without authentication");
            throw new InvalidCredentialsError("You must be logged in to view linked providers");
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
}
