using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Http.Headers;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="DelegatingHandler"/> implementation that handles Hawk authentication for HTTP requests.
/// </summary>
public class HawkDelegatingHandler : DelegatingHandler
{
    private readonly IOptionsMonitor<HawkSettings>? _optionsMonitor;
    private readonly HawkSettings? _hawkSettings;

    /// <summary>
    /// Hawk authentication settings.
    /// </summary>
    public HawkSettings Settings { get => _optionsMonitor?.CurrentValue ?? _hawkSettings!; }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="authId">The authentication Id.</param>
    /// <param name="authKey">The authentication key.</param>
    public HawkDelegatingHandler(string authId, string authKey) : this (new HawkSettings { AuthId = authId, AuthKey = authKey })
    {            
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="hawkSettings">The <see cref="HawkSettings"/>.</param>
    public HawkDelegatingHandler(HawkSettings hawkSettings)
    {
        _hawkSettings = hawkSettings;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HawkSettings"/> instances change.</param>
    public HawkDelegatingHandler(IOptionsMonitor<HawkSettings> optionsMonitor)
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

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (Settings.EnableServerAuthorizationValidation)
        {
            await HandleServerAuthenticateAsync(response, (HawkRawData)authHeader.Properties["HawkRawData"], cancellationToken);
        }
        if (Settings.EnableServerTimeValidation)
        {
            await HandleServerTimeValidateAsync(response, cancellationToken);
        }
        return response;
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

        string? payloadHash = null;
        var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AuthKey);
        if (request.Content != null && Settings.IncludePayloadHash)
        {
            var payload = await request.Content.ReadAsStringAsync(cancellationToken);
            payloadHash = crypto.CalculatePayloadHash(payload, request.Content.Headers.ContentType?.MediaType);
        }

        var timestamp = Settings.TimestampCalculator.Calculate(Settings.TimeOffset);
        var nonce = Settings.NonceGenerator.Generate(Settings.AuthId);

        var hawkRawData = new HawkRawData
        {
            Timestamp = timestamp,
            Nonce = nonce,
            Method = request.Method.Method,
            Resource = request.RequestUri.PathAndQuery,
            Host = request.RequestUri.Host,
            Port = request.RequestUri.Port,
            Hash = payloadHash,
            Ext = await Settings.GetSpecificData(request, Settings),
            App = Settings.App,
            Dlg = Settings.Dlg
        };

        var mac = crypto.CalculateRequestMac(hawkRawData);
        var authVal = new HawkParameters
        {
            Scheme = HawkDefaults.AuthenticationScheme,
            Id = Settings.AuthId,
            Ts = timestamp,
            Nonce = nonce,
            Mac = mac,
            Hash = payloadHash,
            Ext = hawkRawData.Ext,
            App = hawkRawData.App,
            Dlg = hawkRawData.Dlg
        };
        var header = new AuthenticationHeader
        {
            Scheme = authVal.Scheme,
            Parameter = authVal.Parameter
        };
        header.Properties["HawkRawData"] = hawkRawData;
        return header;
    }

    protected virtual async Task HandleServerAuthenticateAsync(HttpResponseMessage response, HawkRawData hawkRawData, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            return;
        }
        if (!response.Headers.TryGetValues("Server-Authorization", out var authorizations))
        {
            return;
        }
        var authorization = authorizations.FirstOrDefault();
        if (authorization == null || !authorization.StartsWith("Hawk "))
        {
            return;
        }
        var saParams = Settings.AuthorizationParameterExtractor.Extract(authorization);
        if (saParams.Count > 4) // sheme, mac, hash, ext
        {
            response.StatusCode = HttpStatusCode.Unauthorized;
            return;
        }
        if (!saParams.TryGetValue("mac", out var mac))
        {
            response.StatusCode = HttpStatusCode.Unauthorized;
            return;
        }
        saParams.TryGetValue("hash", out var hash);
        saParams.TryGetValue("ext", out var ext);

        hawkRawData.Hash = hash;
        hawkRawData.Ext = ext;

        var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AuthKey);
        var macNew = crypto.CalculateResponseMac(hawkRawData);
        if (!mac.Equals(macNew, StringComparison.Ordinal))
        {
            response.StatusCode = HttpStatusCode.Unauthorized;
            return;
        }
        if (hawkRawData.Hash != null)
        {
            var payload = await response.Content.ReadAsStringAsync(cancellationToken);
            var payloadHash = crypto.CalculatePayloadHash(payload, response.Content.Headers.ContentType?.MediaType);
            if (!hawkRawData.Hash.Equals(payloadHash, StringComparison.Ordinal))
            {
                response.StatusCode = HttpStatusCode.Unauthorized;
                return;
            }
        }
    }

    protected virtual async Task HandleServerTimeValidateAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return;
        }
        if (!response.Headers.TryGetValues("WWW-Authenticate", out var authorizations))
        {
            return;
        }

        var authorization = authorizations.FirstOrDefault();
        if (authorization == null || !authorization.StartsWith("Hawk "))
        {
            return;
        }
        var resParams = Settings.AuthorizationParameterExtractor.Extract(authorization);
        if (resParams.Count != 4) // sheme, ts, tsm, error
        {
            return;
        }
        resParams.TryGetValue("ts", out var ts);
        resParams.TryGetValue("tsm", out var tsm);
        if (!String.IsNullOrEmpty(ts) && !String.IsNullOrEmpty(tsm) && long.TryParse(ts, out long tsNew))
        {
            var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AuthKey);
            var tsmNew = crypto.CalculateTsMac(tsNew);
            if (!tsm.Equals(tsmNew, StringComparison.Ordinal))
            {
                throw new HawkTimestampException("Invalid server timestamp hash", tsNew);
            }
        }
        await Task.CompletedTask;
    }
}