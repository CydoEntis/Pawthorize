namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Optional: Provides tenant context for multi-tenant applications.
/// </summary>
public interface ITenantProvider
{
    string? GetCurrentTenantId();
    string? GetTenantSecret();
}