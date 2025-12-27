using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Authentication handler for Hawk authentication in ASP.NET Core
/// </summary>
public class HawkHandler : AuthenticationHandler<HawkOptions>
{
    /// <summary>
    /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    protected new HawkEvents Events
    {
        get { return (HawkEvents)base.Events!; }
        set { base.Events = value; }
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkHandler"/>
    /// </summary>
    /// <param name="options">The monitor used to track options changes</param>
    /// <param name="logger">The logger factory used to create loggers</param>
    /// <param name="encoder">The URL encoder used for URL encoding</param>
    public HawkHandler(IOptionsMonitor<HawkOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    /// <inheritdoc />
    /// <summary>
    /// Handles the authentication process for Hawk authentication
    /// </summary>
    /// <returns>
    /// A task that represents the asynchronous authentication operation, containing the
    /// <see cref="AuthenticateResult"/> of the authentication attempt.
    /// </returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorization))
        {
            return HandleFailureAuthenticateResult("Missing Authorization header.");
        }
        var authorHeaderValue = authorization.First();
        if (authorHeaderValue is null || !authorHeaderValue.StartsWith(HawkDefaults.AuthenticationScheme))
        {
            return HandleFailureAuthenticateResult("Invalid authorization scheme.");
        }

        HawkParameters authParams;
        try
        {
            var rawParams = Options.AuthorizationParameterExtractor.Extract(authorHeaderValue);
            authParams = HawkParameters.Parse(rawParams);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Invalid authorization parameters.");
            return HandleFailureAuthenticateResult("Invalid authorization parameters.");
        }
        if (Options.MaxReplayRequestAge > 0 && Options.ReplayRequestValidator != null)
        {
            string nonceKey = String.IsNullOrWhiteSpace(Options.CacheKeyPrefix) ? authParams.Id : $"{Options.CacheKeyPrefix}||{authParams.Id}||{authParams.Nonce}";
            var result = await Options.ReplayRequestValidator.ValidateAsync(nonceKey, authParams.Nonce, authParams.Ts, Options.MaxReplayRequestAge);
            if (result)
            {
                return HandleFailureAuthenticateResult("Replay request.");
            }
        }

        HawkCredential? credential = null;
        string cacheKey = String.IsNullOrWhiteSpace(Options.CacheKeyPrefix) ? authParams.Id : $"{Options.CacheKeyPrefix}||{authParams.Id}";
        // Get credential from cache.
        if (Options.CredentialCacheTime > 0)
        {
            credential = await Options.CredentialCache.GetCredentialAsync(cacheKey);
        }
        if (credential == null)
        {
            // Get credential from provider.
            credential = await Options.CredentialProvider.GetCredentialAsync(authParams.Id);
            if (credential == null || credential.AuthKey == null)
            {
                return HandleFailureAuthenticateResult("Invalid credential.");
            }
            await Options.CredentialCache.SetCredentialAsync(cacheKey, credential, Options.CredentialCacheTime);
        }

        var crypto = Options.CryptoFactory.Create(credential.HmacAlgorithm, credential.HashAlgorithm, credential.AuthKey);

        if (Options.RequireTimeSkewValidation)
        {
            var serverTimestamp = TimeProvider.GetUtcNow().ToUnixTimeMilliseconds() + Options.TimeOffset;
            if (Math.Abs(serverTimestamp - authParams.Ts * 1000) > Options.TimeSkew * 1000)
            {
                var ts = serverTimestamp / 1000;
                var tsm = crypto.CalculateTsMac(ts);
                return HandleFailureAuthenticateResult("Stale timestamp.", ts, tsm);
            }
        }

        var host = Options.HostResolver.Resolve(Request, Options.ForwardIndex);
        var hawkData = new HawkData
        {
            Timestamp = authParams.Ts,
            Nonce = authParams.Nonce,
            Method = Request.Method,
            Resource = $"{Request.PathBase.ToUriComponent()}{Request.Path.ToUriComponent()}{Request.QueryString.ToUriComponent()}",
            Host = host.Host,
            Port = host.Port!.Value,
            Hash = authParams.Hash,
            Ext = authParams.Ext,
            App = authParams.App,
            Dlg = authParams.Dlg
        };

        var mac = crypto.CalculateRequestMac(hawkData);
        if (!authParams.Mac.Equals(mac, StringComparison.Ordinal))
        {
            return HandleFailureAuthenticateResult("Bad mac.");
        }

        if (authParams.Hash != null)
        {
            Context.Request.EnableBuffering();
            using var reader = new StreamReader(Request.Body, encoding: Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var payload = await reader.ReadToEndAsync();
            try
            {
                var contentType = Request.ContentType?.Split(';')[0];
                var payloadHash = crypto.CalculatePayloadHash(payload, contentType);
                if (!authParams.Hash.Equals(payloadHash, StringComparison.Ordinal))
                {
                    return HandleFailureAuthenticateResult("Bad payload hash.");
                }
            }
            finally
            {
                Request.Body.Position = 0;
            }
        }

        var identity = new ClaimsIdentity(ClaimsIssuer);
        //var identity = new ClaimsIdentity(ClaimsIssuer, ClaimTypes.Name, ClaimTypes.Role);
        var ticket = await CreateTicketAsync(identity, new AuthenticationProperties(), credential);

        if (Options.EnableServerAuthorization && credential.EnableServerAuthorization)
        {
            Context.Items["hawk:credential"] = credential;
            Context.Items["hawk:hawkData"] = hawkData;
        }

        return AuthenticateResult.Success(ticket);
        //return AuthenticateResult.Fail("Authentication failed");
    }

    /// <inheritdoc />
    /// <summary>
    /// Handles the challenge response for unauthorized requests
    /// </summary>
    /// <param name="properties">The authentication properties</param>
    /// <returns>A task that represents the asynchronous challenge operation</returns>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Options.DisableChallenge && Context.Items.TryGetValue("hawk:www-authenticate", out var wwwAuthenticate))
        {
            Response.Headers["WWW-Authenticate"] = (string)wwwAuthenticate!;
        }
        await base.HandleChallengeAsync(properties);
    }

    /// <summary>
    /// Creates an <see cref="AuthenticationTicket"/> from the specified <paramref name="credential"/>
    /// </summary>
    /// <param name="identity">The claims identity</param>
    /// <param name="properties">The authentication properties</param>
    /// <param name="credential">The Hawk credential</param>
    /// <returns>The authentication ticket</returns>
    protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, HawkCredential credential)
    {
        var claims = new[] { new Claim(ClaimTypes.Name, credential.User ?? credential.AuthId), new Claim(ClaimTypes.NameIdentifier, credential.AuthId) };
        identity.AddClaims(claims);
        var context = new HawkCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options);
        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }

    /// <summary>
    /// Handles authentication failure by creating an appropriate failure result
    /// </summary>
    /// <param name="failureMessage">The failure message describing the authentication failure</param>
    /// <param name="ts">Optional server timestamp for clock synchronization (used when timestamp validation fails)</param>
    /// <param name="tsm">Optional timestamp MAC for clock synchronization (used when timestamp validation fails)</param>
    /// <returns>An authentication failure result</returns>
    protected virtual AuthenticateResult HandleFailureAuthenticateResult(string failureMessage, long? ts = null, string? tsm = null)
    {
        if (!Options.DisableChallenge)
        {
            var t = ts == null ? String.Empty : $" ts=\"{ts}\", tsm=\"{tsm}\",";
            var wwwAuthenticate = $"{HawkDefaults.AuthenticationScheme}{t} error=\"{failureMessage}\"";
            Context.Items["hawk:www-authenticate"] = wwwAuthenticate;
        }
        return AuthenticateResult.Fail(failureMessage);
    }
}