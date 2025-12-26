using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Authentication handler for Hmac authentication.
/// </summary>
public class HmacHandler : AuthenticationHandler<HmacOptions>
{
    /// <summary>
    /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    protected new HmacEvents Events
    {
        get { return (HmacEvents)base.Events!; }
        set { base.Events = value; }
    }

    /// <summary>
    /// Initializes a new instance of <see cref="HmacHandler"/>.
    /// </summary>
    /// <inheritdoc />
    public HmacHandler(IOptionsMonitor<HmacOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authorization))
        {
            return HandleFailureAuthenticateResult("Missing Authorization header.");
        }
        var authorHeaderValue = authorization.First();
        if (!authorHeaderValue.StartsWith(HmacDefaults.AuthenticationScheme))
        {
            return HandleFailureAuthenticateResult("Invalid authorization scheme.");
        }

        HmacParameters authParams;
        try
        {
            var rawParams = Options.AuthorizationParameterExtractor.Extract(authorHeaderValue);
            if (rawParams.Count != 6)
            {
                return HandleFailureAuthenticateResult("Error authorization parameters.");
            }
            authParams = HmacParameters.Parse(rawParams);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Invalid authorization parameters.");
            return HandleFailureAuthenticateResult("Invalid authorization parameters.");
        }
        if (Options.MaxReplayRequestAge > 0)
        {
            string nonceKey = String.IsNullOrWhiteSpace(Options.CacheKeyPrefix) ? authParams.AppId : $"{Options.CacheKeyPrefix}||{authParams.AppId}||{authParams.Nonce}";
            var result = await Options.ReplayRequestValidator.ValidateAsync(nonceKey, authParams.Nonce, authParams.Timestamp, Options.MaxReplayRequestAge);
            if (result)
            {
                return HandleFailureAuthenticateResult("Replay request.");
            }
        }

        HmacCredential? credential = null;
        string cacheKey = String.IsNullOrWhiteSpace(Options.CacheKeyPrefix) ? authParams.AppId : $"{Options.CacheKeyPrefix}||{authParams.AppId}";
        // Get credential from cache.
        if (Options.CredentialCacheTime > 0)
        {
            credential = await Options.CredentialCache.GetCredentialAsync(cacheKey);
        }
        if (credential == null)
        {
            // Get credential from provider.
            credential = await Options.CredentialProvider.GetCredentialAsync(authParams.AppId);
            if (credential == null || credential.AppKey == null)
            {
                return HandleFailureAuthenticateResult("Invalid credential.");
            }
            await Options.CredentialCache.SetCredentialAsync(cacheKey, credential, Options.CredentialCacheTime);
        }

        var crypto = Options.CryptoFactory.Create(credential.HmacAlgorithm, credential.HashAlgorithm, credential.AppKey);

        if (Options.RequireTimeSkewValidation)
        {
            var serverTimestamp = TimeProvider.GetUtcNow().ToUnixTimeMilliseconds() + Options.TimeOffset;
            if (Math.Abs(serverTimestamp - authParams.Timestamp * 1000) > Options.TimeSkew * 1000)
            {
                return HandleFailureAuthenticateResult("Stale timestamp.");
            }
        }

        // {appId}\n{timestamp}\n{nonce}\n{method}\n{resource}\n{host}\n{port}\n{payloadHash}
        var resource = $"{Request.PathBase.ToUriComponent()}{Request.Path.ToUriComponent()}{Request.QueryString.ToUriComponent()}";

        var host = Options.HostResolver.Resolve(Request, Options.ForwardIndex);
        var rawData = $"{authParams.AppId}\n{authParams.Timestamp}\n{authParams.Nonce}\n{Request.Method}\n{resource}\n{host.Host}\n{host.Port!.Value}\n{authParams.PayloadHash}";
        var signature = crypto.CalculateMac(rawData);
        if (!authParams.Signature.Equals(signature, StringComparison.Ordinal))
        {
            return HandleFailureAuthenticateResult("Bad mac.");
        }

        if (!String.IsNullOrWhiteSpace(authParams.PayloadHash))
        {
            Context.Request.EnableBuffering();
            using var reader = new StreamReader(Request.Body, encoding: Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var payload = await reader.ReadToEndAsync();
            try
            {
                var payloadHash = crypto.CalculateHash(payload);
                if (!authParams.PayloadHash.Equals(payloadHash, StringComparison.Ordinal))
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

        return AuthenticateResult.Success(ticket);
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (!Options.DisableChallenge && Context.Items.TryGetValue("hawk:www-authenticate", out var wwwAuthenticate))
        {
            Response.Headers["WWW-Authenticate"] = (string)wwwAuthenticate!;
        }
        await base.HandleChallengeAsync(properties);
    }

    /// <summary>
    /// Creates an <see cref="AuthenticationTicket"/> from the specified <paramref name="credential"/>.
    /// </summary>
    /// <param name="identity">The <see cref="ClaimsIdentity"/>.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="credential">The <see cref="HmacCredential"/>.</param>
    /// <returns>The <see cref="AuthenticationTicket"/>.</returns>
    protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, HmacCredential credential)
    {
        var claims = new[] { new Claim(ClaimTypes.Name, credential.AppId), new Claim(ClaimTypes.NameIdentifier, credential.AppId) };
        identity.AddClaims(claims);
        var context = new HmacCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options);
        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }

    protected virtual AuthenticateResult HandleFailureAuthenticateResult(string failureMessage)
    {
        if (!Options.DisableChallenge)
        {
            var wwwAuthenticate = $"{HmacDefaults.AuthenticationScheme} error=\"{failureMessage}\"";
            Context.Items["hawk:www-authenticate"] = wwwAuthenticate;
        }
        return AuthenticateResult.Fail(failureMessage);
    }
}