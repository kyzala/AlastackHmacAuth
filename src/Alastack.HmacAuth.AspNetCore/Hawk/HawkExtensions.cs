using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to configure Hawk authentication.
/// </summary>
public static class HawkExtensions
{
    /// <summary>
    /// Adds Hawk based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HawkDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHawk(this AuthenticationBuilder builder)
        => builder.AddHawk(HawkDefaults.AuthenticationScheme, _ => { });

    /// <summary>
    /// Adds Hawk based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HawkDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HawkOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHawk(this AuthenticationBuilder builder, Action<HawkOptions> configureOptions)
        => builder.AddHawk(HawkDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds Hawk based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HawkDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HawkOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHawk(this AuthenticationBuilder builder, string authenticationScheme, Action<HawkOptions> configureOptions)
        => builder.AddHawk(authenticationScheme, HawkDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds Hawk based authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="HawkDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="HawkOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddHawk(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<HawkOptions> configureOptions)
    {
        builder.Services.AddSingleton<IDataCache, DataCache>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<HawkOptions>, HawkPostConfigureOptions>());
        return builder.AddScheme<HawkOptions, HawkHandler>(authenticationScheme, displayName, configureOptions);
    }
}