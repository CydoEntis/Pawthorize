using Microsoft.AspNetCore.Builder;
using Pawthorize.Middleware;

namespace Pawthorize.Extensions;

/// <summary>
/// Extension methods for configuring Pawthorize middleware in the application pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Add Pawthorize CSRF protection middleware.
    /// This middleware automatically validates CSRF tokens for state-changing requests
    /// when using HttpOnlyCookies or Hybrid token delivery modes.
    ///
    /// IMPORTANT: Must be called AFTER UseRouting() and BEFORE UseAuthentication().
    /// </summary>
    /// <param name="app">Application builder</param>
    /// <returns>Application builder for chaining</returns>
    /// <example>
    /// app.UseRouting();
    /// app.UsePawthorizeCsrf(); // Add CSRF protection
    /// app.UseAuthentication();
    /// app.UseAuthorization();
    /// </example>
    public static IApplicationBuilder UsePawthorizeCsrf(this IApplicationBuilder app)
    {
        return app.UseMiddleware<CsrfProtectionMiddleware>();
    }
}
