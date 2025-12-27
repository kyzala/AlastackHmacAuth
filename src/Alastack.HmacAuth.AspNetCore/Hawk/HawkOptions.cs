using Alastack.HmacAuth.Credentials;
using Microsoft.AspNetCore.Authentication;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Configuration options for <see cref="HawkHandler"/>.
/// </summary>
public class HawkOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Reverse host index of forwarding header. Using 0 base index.
    /// </summary>
    public int ForwardIndex { get; set; }

    /// <summary>
    /// Whether time skew validation is required. Defaults to <c>true</c>.
    /// </summary>
    public bool RequireTimeSkewValidation { get; set; } = true;

    /// <summary>
    /// Optional number of seconds of permitted clock skew for incoming timestamps.
    /// Provides a +/- skew which means actual allowed window is double the number of seconds.
    /// Defaults to <c>300</c> seconds.
    /// </summary>
    public long TimeSkew { get; set; } = 300;

    /// <summary>
    /// Set the offset in milliseconds to adjust the service time. Defaults to <c>0</c> millisecond.
    /// </summary>
    public long TimeOffset { get; set; }

    /// <summary>
    /// Max replay request age. Defaults to <c>60</c> seconds.
    /// If the value is <c>0</c>, the replay request verification will be disabled.
    /// </summary>
    public long MaxReplayRequestAge { get; set; } = 60;

    /// <summary>
    /// Credential cache time. Defaults to <c>60</c> seconds.
    /// If the value is <c>0</c>, the credential cache will be disabled.
    /// </summary>
    public long CredentialCacheTime { get; set; } = 60;

    /// <summary>
    /// Cache key prefix for nonce and credential.
    /// </summary>
    public string? CacheKeyPrefix { get; set; } = "hawk";

    /// <summary>
    /// Whether to enable server-authentication.
    /// </summary>
    public bool EnableServerAuthorization { get; set; }

    /// <summary>
    /// Whether to include the hash value of the Http response payload when server-authentication is enabled.
    /// </summary>
    public bool IncludeResponsePayloadHash { get; set; } = true;

    /// <summary>
    /// Override this method to deal with 401 challenge concerns, 
    /// if an authentication scheme in question deals an authentication interaction as part of it's request flow.
    /// </summary>
    public bool DisableChallenge { get; set; } = true;

    /// <summary>
    /// <see cref="IReplayRequestValidator"/> interface. The default implementation is <see cref="Alastack.HmacAuth.AspNetCore.ReplayRequestValidator"/>.
    /// If the value is <c>null</c>, the replay request verification will be disabled.
    /// </summary>
    public IReplayRequestValidator? ReplayRequestValidator { get; set; }

    /// <summary>
    /// <see cref="ICryptoFactory"/> interface. The default implementation is <see cref="DefaultCryptoFactory"/>.
    /// </summary>
    public ICryptoFactory CryptoFactory { get; set; } = default!;

    /// <summary>
    /// <see cref="IHostResolver"/> interface. The default implementation is <see cref="DefaultHostResolver"/>.
    /// </summary>
    public IHostResolver HostResolver { get; set; } = default!;

    /// <summary>
    /// <see cref="IAuthorizationParameterExtractor"/> interface. The default implementation is <see cref="HawkParameterExtractor"/>.
    /// </summary>
    public IAuthorizationParameterExtractor AuthorizationParameterExtractor { get; set; } = default!;

    /// <summary>
    /// <see cref="ICredentialProvider{TCredential}"/> interface.
    /// </summary>
    public ICredentialProvider<HawkCredential> CredentialProvider { get; set; } = default!;

    /// <summary>
    /// <see cref="ICredentialCache{TCredential}"/> interface.
    /// </summary>
    public ICredentialCache<HawkCredential> CredentialCache { get; set; } = default!;

    /// <summary>
    /// The Provider may be assigned to an instance of an object created by the application at startup time. The handler
    /// calls methods on the provider which give the application control at certain points where processing is occurring.
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    public new HawkEvents Events
    {
        get => (HawkEvents)base.Events!;
        set => base.Events = value;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkOptions"/>.
    /// </summary>
    public HawkOptions()
    {
        Events = new HawkEvents();
    }

    /// <summary>
    /// Check that the options are valid. Should throw an exception if things are not ok.
    /// </summary>
    public override void Validate()
    {
        base.Validate();

        if (ForwardIndex < 0)
        {
            throw new ArgumentException($"{nameof(ForwardIndex)} must be greater than or equal to zero.", nameof(ForwardIndex));
        }

        if (MaxReplayRequestAge < 0)
        {
            throw new ArgumentException($"{nameof(MaxReplayRequestAge)} must be greater than or equal to zero.", nameof(MaxReplayRequestAge));
        }

        if (CredentialCacheTime < 0)
        {
            throw new ArgumentException($"{nameof(CredentialCacheTime)} must be greater than or equal to zero.", nameof(CredentialCacheTime));
        }

        if (CredentialProvider == null)
        {
            throw new ArgumentException($"{nameof(CredentialProvider)} must be provided.", nameof(CredentialProvider));
        }
    }


}