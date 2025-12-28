namespace Pawthorize.Core.Models;

/// <summary>
/// Configuration for Platform mode (future - Phase 4)
/// </summary>
public class PlatformOptions
{
    /// <summary>
    /// URL of the Pawthorize Platform server
    /// Example: "https://auth.mycompany.com"
    /// </summary>
    public string ServerUrl { get; set; } = string.Empty;
    
    /// <summary>
    /// Application ID from Platform dashboard
    /// Example: "app_abc123"
    /// </summary>
    public string ApplicationId { get; set; } = string.Empty;
    
    /// <summary>
    /// API key from Platform dashboard
    /// Example: "sk_live_abc123..."
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;
}