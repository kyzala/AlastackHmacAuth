using Microsoft.AspNetCore.Builder;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Extension methods to add Hawk authentication capabilities to an HTTP application pipeline.
/// </summary>
public static class HawkMiddlewareExtentions
{
    /// <summary>
    /// Adds the <see cref="HawkMiddleware"/> to the specified <see cref="IApplicationBuilder"/>, which enables Hawk server authentication capabilities.
    /// </summary>
    /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static IApplicationBuilder UseHawkServerAuthorization(this IApplicationBuilder app)
    {
        return app.UseMiddleware<HawkMiddleware>();
    }
}