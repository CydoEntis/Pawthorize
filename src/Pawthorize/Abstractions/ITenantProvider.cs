namespace Pawthorize.Abstractions;

/// <summary>
/// Optional: Provides tenant context for multi-tenant applications.
/// </summary>
public interface ITenantProvider
{
    /// <summary>
    /// Gets the current tenant identifier.
    /// </summary>
    /// <returns>The tenant ID, or null if not in a multi-tenant context.</returns>
    string? GetCurrentTenantId();

    /// <summary>
    /// Gets the JWT secret for the current tenant.
    /// </summary>
    /// <returns>The tenant-specific secret, or null to use the global secret.</returns>
    string? GetTenantSecret();
}