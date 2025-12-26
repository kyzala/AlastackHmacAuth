using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to configure Hmac authentication.
/// </summary>
public static class HmacExtensions
{
    /// <summary>
    /// Adds Hmac based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HmacDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder)
        => builder.AddHmac(HmacDefaults.AuthenticationScheme, _ => { });

    /// <summary>
    /// Adds Hmac based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HmacDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HmacOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, Action<HmacOptions> configureOptions)
        => builder.AddHmac(HmacDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds Hmac based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HmacDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HmacOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, string authenticationScheme, Action<HmacOptions> configureOptions)
        => builder.AddHmac(authenticationScheme, HmacDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds Hmac based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HmacDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HmacOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHmac(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<HmacOptions> configureOptions)
    {
        builder.Services.AddSingleton<IDataCache, DataCache>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<HmacOptions>, HmacPostConfigureOptions>());
        return builder.AddScheme<HmacOptions, HmacHandler>(authenticationScheme, displayName, configureOptions);
    }
}