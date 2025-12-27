using System.Net;
using System.Net.Http.Headers;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="DelegatingHandler"/> implementation that handles Hawk authentication for HTTP requests.
/// </summary>
public class HawkDelegatingHandler : DelegatingHandler
{
    private readonly HawkSettings? _hawkSettings;

    /// <summary>
    /// Gets the Hawk authentication settings
    /// </summary>
    public virtual HawkSettings Settings  => _hawkSettings!;

    /// <summary>
    /// Initializes a new instance of the <see cref="HawkDelegatingHandler"/> class
    /// </summary>
    protected HawkDelegatingHandler() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="HawkDelegatingHandler"/> class
    /// </summary>
    /// <param name="authId">The authentication identifier (client ID)</param>
    /// <param name="authKey">The authentication key (shared secret)</param>
    public HawkDelegatingHandler(string authId, string authKey) : this (new HawkSettings { AuthId = authId, AuthKey = authKey })
    {            
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HawkDelegatingHandler"/> class
    /// with Hawk settings
    /// </summary>
    /// <param name="hawkSettings">The Hawk authentication settings</param>
    public HawkDelegatingHandler(HawkSettings hawkSettings)
    {
        _hawkSettings = hawkSettings;
    }

    /// <summary>
    /// Sends an HTTP request to the inner handler to send to the server as an asynchronous operation
    /// </summary>
    /// <param name="request">The HTTP request message to send to the server</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation</param>
    /// <returns>
    /// The task object representing the asynchronous operation
    /// </returns>
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
            await HandleServerAuthenticateAsync(response, (HawkData)authHeader.Properties["HawkData"], cancellationToken);
        }
        if (Settings.EnableServerTimeValidation)
        {
            await HandleServerTimeValidateAsync(response, cancellationToken);
        }
        return response;
    }

    /// <summary>
    /// Creates an authentication header for the HTTP request
    /// </summary>
    /// <param name="request">The HTTP request message to send to the server</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation</param>
    /// <returns>
    /// An <see cref="AuthenticationHeader"/> containing the Hawk authentication information
    /// </returns>
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

        var hawkData = new HawkData
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

        var mac = crypto.CalculateRequestMac(hawkData);
        var authVal = new HawkParameters
        {
            Scheme = HawkDefaults.AuthenticationScheme,
            Id = Settings.AuthId,
            Ts = timestamp,
            Nonce = nonce,
            Mac = mac,
            Hash = payloadHash,
            Ext = hawkData.Ext,
            App = hawkData.App,
            Dlg = hawkData.Dlg
        };
        var header = new AuthenticationHeader
        {
            Scheme = authVal.Scheme,
            Parameter = authVal.Parameter
        };
        header.Properties["HawkData"] = hawkData;
        return header;
    }

    /// <summary>
    /// Validates the server's authentication response
    /// </summary>
    /// <param name="response">The HTTP response received from the server</param>
    /// <param name="hawkData">The Hawk authentication data used in the original request</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation</param>
    /// <returns>A task representing the asynchronous validation operation</returns>
    protected virtual async Task HandleServerAuthenticateAsync(HttpResponseMessage response, HawkData hawkData, CancellationToken cancellationToken)
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

        hawkData.Hash = hash;
        hawkData.Ext = ext;

        var crypto = Settings.CryptoFactory.Create(Settings.HmacAlgorithm, Settings.HashAlgorithm, Settings.AuthKey);
        var macNew = crypto.CalculateResponseMac(hawkData);
        if (!mac.Equals(macNew, StringComparison.Ordinal))
        {
            response.StatusCode = HttpStatusCode.Unauthorized;
            return;
        }
        if (hawkData.Hash != null)
        {
            var payload = await response.Content.ReadAsStringAsync(cancellationToken);
            var payloadHash = crypto.CalculatePayloadHash(payload, response.Content.Headers.ContentType?.MediaType);
            if (!hawkData.Hash.Equals(payloadHash, StringComparison.Ordinal))
            {
                response.StatusCode = HttpStatusCode.Unauthorized;
                return;
            }
        }
    }

    /// <summary>
    /// Validates server timestamp when authentication fails
    /// </summary>
    /// <param name="response">The HTTP response received from the server</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation</param>
    /// <returns>A task representing the asynchronous validation operation</returns>
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