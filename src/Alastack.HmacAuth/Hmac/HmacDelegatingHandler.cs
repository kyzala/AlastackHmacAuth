using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="DelegatingHandler"/> implementation that handles Hmac authentication for HTTP requests.
/// </summary>
public class HmacDelegatingHandler : DelegatingHandler
{
    private readonly HmacSettings? _hmacSettings;

    private readonly ILogger? _logger;

    /// <summary>
    /// Hmac authentication settings.
    /// </summary>
    public virtual HmacSettings Settings => _hmacSettings!;

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    protected HmacDelegatingHandler() { }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="logger">The optional logger.</param>
    protected HmacDelegatingHandler(ILogger? logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="appId">The app Id.</param>
    /// <param name="appSecret">The app secret.</param>
    public HmacDelegatingHandler(string appId, string appSecret) : this(new HmacSettings { AppId = appId, AppSecret = appSecret })
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="hmacSettings">The <see cref="HmacSettings"/>.</param>
    /// <param name="logger">The optional logger.</param>
    public HmacDelegatingHandler(HmacSettings hmacSettings, ILogger<HmacDelegatingHandler>? logger = null)
    {
        _hmacSettings = hmacSettings;
        _logger = logger;
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
        var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AppSecret);
        if (request.Content != null && Settings.IncludePayloadHash)
        {
            var payload = await request.Content.ReadAsStringAsync(cancellationToken);
            payloadHash = crypto.CalculateHash(payload);
        }

        var timestamp = Settings.TimestampCalculator.Calculate(Settings.TimeOffsetSeconds);
        var nonce = Settings.NonceGenerator.Generate(Settings.AppId);

        // {appId}\n{timestamp}\n{nonce}\n{method}\n{resource}\n{host}\n{port}\n{payloadHash}
        var hmacData = $"{Settings.AppId}\n{timestamp}\n{nonce}\n{request.Method.Method}\n{request.RequestUri.PathAndQuery}\n{request.RequestUri.Host}\n{request.RequestUri.Port}\n{payloadHash}";
        var signature = crypto.CalculateMac(hmacData);
        var parameter = $"{Settings.AppId}:{timestamp}:{nonce}:{signature}:{payloadHash}";

        _logger?.LogDebug("Hmac request signed. AppId={AppId} Method={Method} Uri={Uri} Timestamp={Timestamp}",
            Settings.AppId, request.Method.Method, request.RequestUri, timestamp);

        return new AuthenticationHeader
        {
            Scheme = HmacDefaults.AuthenticationScheme,
            Parameter = parameter
        };
    }
}