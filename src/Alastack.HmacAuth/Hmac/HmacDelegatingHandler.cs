using Microsoft.Extensions.Options;
using System.Net.Http.Headers;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="DelegatingHandler"/> implementation that handles Hmac authentication for HTTP requests.
/// </summary>
public class HmacDelegatingHandler : DelegatingHandler
{
    private readonly IOptionsMonitor<HmacSettings>? _optionsMonitor;
    private readonly HmacSettings? _hmacSettings;

    /// <summary>
    /// Hmac authentication settings.
    /// </summary>
    public HmacSettings Settings { get => _optionsMonitor?.CurrentValue ?? _hmacSettings!; }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="appId">The app Id.</param>
    /// <param name="appKey">The app key.</param>
    public HmacDelegatingHandler(string appId, string appKey) : this(new HmacSettings { AppId = appId, AppKey = appKey })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="hmacSettings">The <see cref="HmacSettings"/>.</param>
    public HmacDelegatingHandler(HmacSettings hmacSettings)
    {
        _hmacSettings = hmacSettings;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HmacSettings"/> instances change.</param>
    public HmacDelegatingHandler(IOptionsMonitor<HmacSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var authHeader = await CreateAuthenticationHeaderAsync(request, cancellationToken);
        if (authHeader.IsGenericHeaderName)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(authHeader.Scheme, authHeader.Parameter);
        }
        else
        {
            request.Headers.Add(authHeader.HeaderName, $"{authHeader.Scheme} {authHeader.Parameter}");
        }
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creating an authentication Header.
    /// </summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    /// <exception cref="NullReferenceException">If the request uri is <c>null</c>, an exception will be thrown.</exception>
    protected virtual async Task<AuthenticationHeader> CreateAuthenticationHeaderAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri == null)
        {
            throw new NullReferenceException("request.RequestUri is null.");
        }

        string payloadHash = String.Empty;
        var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AppKey);
        if (request.Content != null && Settings.IncludePayloadHash)
        {
            var payload = await request.Content.ReadAsStringAsync(cancellationToken);
            payloadHash = crypto.CalculateHash(payload);
        }

        var timestamp = Settings.TimestampCalculator.Calculate(Settings.TimeOffset);
        var nonce = Settings.NonceGenerator.Generate(Settings.AppId);

        // {appId}\n{timestamp}\n{nonce}\n{method}\n{resource}\n{host}\n{port}\n{payloadHash}
        var rawData = $"{Settings.AppId}\n{timestamp}\n{nonce}\n{request.Method.Method}\n{request.RequestUri.PathAndQuery}\n{request.RequestUri.Host}\n{request.RequestUri.Port}\n{payloadHash}";
        var signature = crypto.CalculateMac(rawData);
        var parameter = $"{Settings.AppId}:{timestamp}:{nonce}:{signature}:{payloadHash}";

        return new AuthenticationHeader
        {
            Scheme = HmacDefaults.AuthenticationScheme,
            Parameter = parameter
        };
    }
}