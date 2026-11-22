using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Used to setup defaults for the <see cref="HawkOptions"/>.
/// </summary>
public class HawkPostConfigureOptions : IPostConfigureOptions<HawkOptions>
{
    private readonly IDataCache _dataCache;

    private readonly ILoggerFactory? _loggerFactory;

    /// <summary>
    /// Initializes the <see cref="HawkPostConfigureOptions"/>.
    /// </summary>
    /// <param name="dataCache">The <see cref="IDataCache"/>.</param>
    /// <param name="loggerFactory">The optional logger factory used by the default cache and replay validator.</param>
    public HawkPostConfigureOptions(IDataCache dataCache, ILoggerFactory? loggerFactory = null)
    {
        _dataCache = dataCache;
        _loggerFactory = loggerFactory;
    }

    /// <summary>
    /// Invoked to post configure a <see cref="HawkOptions"/> instance.
    /// </summary>
    /// <param name="name">The name of the <see cref="HawkOptions"/> instance being configured.</param>
    /// <param name="options">The <see cref="HawkOptions"/> instance to configure.</param>
    public void PostConfigure(string? name, HawkOptions options)
    {
        options.ReplayRequestValidator ??= new ReplayRequestValidator(_dataCache, _loggerFactory?.CreateLogger<ReplayRequestValidator>());
        options.CredentialCache ??= new CredentialCache<HawkCredential>(_dataCache, _loggerFactory?.CreateLogger<CredentialCache<HawkCredential>>());
        options.CryptoFactory ??= new DefaultCryptoFactory();
        options.AuthorizationParameterExtractor ??= new HawkParameterExtractor();
        options.HostResolver ??= new DefaultHostResolver();
    }
}