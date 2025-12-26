using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Used to setup defaults for the <see cref="HmacOptions"/>.
/// </summary>
public class HmacPostConfigureOptions : IPostConfigureOptions<HmacOptions>
{
    private readonly IDataCache _dataCache;

    /// <summary>
    /// Initializes the <see cref="HmacPostConfigureOptions"/>.
    /// </summary>
    /// <param name="dataCache">The <see cref="IDataCache"/>.</param>
    public HmacPostConfigureOptions(IDataCache dataCache)
    {
        _dataCache = dataCache;
    }

    /// <summary>
    /// Invoked to post configure a <see cref="HmacOptions"/> instance.
    /// </summary>
    /// <param name="name">The name of the <see cref="HmacOptions"/> instance being configured.</param>
    /// <param name="options">The <see cref="HmacOptions"/> instance to configure.</param>
    public void PostConfigure(string? name, HmacOptions options)
    {
        options.ReplayRequestValidator ??= new ReplayRequestValidator(_dataCache);
        options.CredentialCache ??= new CredentialCache<HmacCredential>(_dataCache);
        options.CryptoFactory ??= new DefaultCryptoFactory();
        options.AuthorizationParameterExtractor ??= new HmacParameterExtractor();
        options.HostResolver ??= new DefaultHostResolver();
    }
}