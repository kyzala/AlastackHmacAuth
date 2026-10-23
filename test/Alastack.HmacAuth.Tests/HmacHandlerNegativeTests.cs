using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Text;

namespace Alastack.HmacAuth.Tests;

/// <summary>
/// Negative-path tests for <see cref="HmacHandler"/>: every failure must produce
/// 401 with a <c>WWW-Authenticate: Hmac error="..."</c> challenge.
/// </summary>
public class HmacHandlerNegativeTests
{
    private static readonly HmacCredential Credential = new()
    {
        AppId = "id123",
        AppKey = "3@uo45er?",
        HmacAlgorithm = "HMACSHA256",
        HashAlgorithm = "SHA256"
    };

    private static long NowSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static void ConfigureWebHost(IWebHostBuilder webBuilder)
    {
        webBuilder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddMemoryCache();
                services.AddRouting();
                services.AddAuthorization();
                services.AddAuthentication(options => options.DefaultScheme = HmacDefaults.AuthenticationScheme)
                    .AddHmac(options =>
                    {
                        options.DisableChallenge = false; // emit the WWW-Authenticate challenge header
                        options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(
                            new Dictionary<string, HmacCredential> { [Credential.AppId] = Credential });
                    });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/api/TodoItems/{id}", () => "Ok").RequireAuthorization();
                    endpoints.MapPost("/api/TodoItems", () => "Ok").RequireAuthorization();
                });
            });
    }

    private static async Task<HttpResponseMessage> SendAsync(string? authorization)
    {
        using var host = await new HostBuilder().ConfigureWebHost(ConfigureWebHost).StartAsync();
        using var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://example.com");
        using var client = server.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "api/TodoItems/1");
        if (authorization != null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }
        return await client.SendAsync(request);
    }

    /// <summary>
    /// Computes a valid Hmac Authorization header for the given values.
    /// </summary>
    private static string ComputeAuthorization(string appId, long timestamp, string nonce, string payloadHash,
        string method = "GET", string resource = "/api/TodoItems/1")
    {
        var crypto = new DefaultCryptoFactory().Create(Credential.HmacAlgorithm, Credential.HashAlgorithm, Credential.AppKey);
        var macNormalize = $"{appId}\n{timestamp}\n{nonce}\n{method}\n{resource}\nexample.com\n80\n{payloadHash}";
        var signature = crypto.CalculateMac(macNormalize);
        // wire format: Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}
        return $"Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}";
    }

    [Fact]
    public async Task MissingAuthorizationHeader_Returns401()
    {
        var response = await SendAsync(null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Missing Authorization header.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task InvalidScheme_Returns401()
    {
        var response = await SendAsync("Bearer some-token");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Invalid authorization scheme.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task InvalidParameters_Returns401()
    {
        // only 4 raw parameters instead of 6
        var response = await SendAsync($"Hmac id123:{NowSeconds()}:nonce123");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Error authorization parameters.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task UnknownCredential_Returns401()
    {
        var response = await SendAsync($"Hmac unknown:{NowSeconds()}:nonce123::AAAA");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Invalid credential.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task StaleTimestamp_Returns401()
    {
        var staleTimestamp = NowSeconds() - 3600; // far outside the 300s default skew
        var response = await SendAsync($"Hmac id123:{staleTimestamp}:nonce123::AAAA");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Stale timestamp.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task BadMac_Returns401()
    {
        var authorization = $"Hmac id123:{NowSeconds()}:nonce123:AAAABBBBCCCC:";
        var response = await SendAsync(authorization);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bad mac.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task BadPayloadHash_Returns401()
    {
        // the signature is valid for payloadHash "abcdef", but the actual body hashes differently
        var timestamp = NowSeconds();
        var nonce = Guid.NewGuid().ToString("N");
        var authorization = ComputeAuthorization("id123", timestamp, nonce, "abcdef", "POST", "/api/TodoItems");

        using var host = await new HostBuilder().ConfigureWebHost(ConfigureWebHost).StartAsync();
        using var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://example.com");
        using var client = server.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/TodoItems")
        {
            Content = new StringContent("test", Encoding.UTF8)
        };
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bad payload hash.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task ReplayedNonce_Returns401()
    {
        var timestamp = NowSeconds();
        var nonce = Guid.NewGuid().ToString("N");
        var authorization = ComputeAuthorization("id123", timestamp, nonce, "");

        using var host = await new HostBuilder().ConfigureWebHost(ConfigureWebHost).StartAsync();
        using var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://example.com");
        using var client = server.CreateClient();

        using var first = new HttpRequestMessage(HttpMethod.Get, "api/TodoItems/1");
        first.Headers.TryAddWithoutValidation("Authorization", authorization);
        var firstResponse = await client.SendAsync(first);
        Assert.True(firstResponse.StatusCode == HttpStatusCode.OK, $"first request failed: {firstResponse.Headers.WwwAuthenticate}"); // authenticated

        using var second = new HttpRequestMessage(HttpMethod.Get, "api/TodoItems/1");
        second.Headers.TryAddWithoutValidation("Authorization", authorization);
        var secondResponse = await client.SendAsync(second);
        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
        Assert.Contains("Replay request.", secondResponse.Headers.WwwAuthenticate.ToString());
    }
}
