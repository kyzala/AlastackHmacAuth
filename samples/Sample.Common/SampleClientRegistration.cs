using Alastack.HmacAuth;
using Alastack.HmacAuth.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Sample.Common;

/// <summary>
/// Shared client-side authentication registration for the samples:
/// settings, options validation and the injectable delegating handler.
/// </summary>
public static class SampleClientRegistration
{
    /// <summary>
    /// Registers <see cref="HmacSettings"/>, validation and <see cref="OptionsHmacDelegatingHandler"/>.
    /// The returned handler must still be attached to an HttpClient via
    /// <c>AddHttpMessageHandler&lt;InjectableHmacDelegatingHandler&gt;()</c>.
    /// </summary>
    public static IServiceCollection AddSampleHmacAuth(this IServiceCollection services)
    {
        services.Configure<HmacSettings>(options =>
        {
            options.AppId = SampleCredentials.AppId;
            options.AppKey = SampleCredentials.AppKey;
        });
        services.AddSingleton<IValidateOptions<HmacSettings>, HmacConfigValidation>();
        services.AddTransient<OptionsHmacDelegatingHandler>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="HawkSettings"/>, validation and <see cref="OptionsHawkDelegatingHandler"/>.
    /// </summary>
    public static IServiceCollection AddSampleHawkAuth(this IServiceCollection services)
    {
        services.Configure<HawkSettings>(options =>
        {
            options.AuthId = SampleCredentials.AppId;
            options.AuthKey = SampleCredentials.AppKey;
            options.App = SampleCredentials.HawkApp;
            options.Dlg = SampleCredentials.HawkDlg;
            options.EnableServerAuthorizationValidation = true;
            options.GetSpecificData = (request, settings) => Task.FromResult<string?>(SampleCredentials.HawkSpecificData);
        });
        services.AddSingleton<IValidateOptions<HawkSettings>, HawkConfigValidation>();
        services.AddTransient<OptionsHawkDelegatingHandler>();
        return services;
    }
}
