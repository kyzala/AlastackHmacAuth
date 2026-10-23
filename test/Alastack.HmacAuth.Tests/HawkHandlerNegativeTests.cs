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
/// Negative-path tests for <see cref="HawkHandler"/>: every failure must produce
/// 401 with a <c>WWW-Authenticate: Hawk error="..."</c> challenge.
/// </summary>
public class HawkHandlerNegativeTests
{
    private static readonly HawkCredential Credential = new()
    {
        AuthId = "id123",
        AuthKey = "3@uo45er?",
        HmacAlgorithm = "HMACSHA256",
        HashAlgorithm = "SHA256"
    };

    private static long NowSeconds() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static void ConfigureWebHost(IWebHostBuilder webBuilder, bool enableServerAuthorization = false)
    {
        webBuilder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddMemoryCache();
                services.AddRouting();
                services.AddAuthorization();
                services.AddAuthentication(options => options.DefaultScheme = HawkDefaults.AuthenticationScheme)
                    .AddHawk(options =>
                    {
                        options.DisableChallenge = false; // emit the WWW-Authenticate challenge header
                        options.EnableServerAuthorization = enableServerAuthorization;
                        options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(
                            new Dictionary<string, HawkCredential> { [Credential.AuthId] = Credential });
                    });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                if (enableServerAuthorization)
                {
                    app.UseHawkServerAuthorization();
                }
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/api/TodoItems/{id}", () => "Ok").RequireAuthorization();
                    endpoints.MapPost("/api/TodoItems", () => "Ok").RequireAuthorization();
                });
            });
    }

    private static async Task<HttpResponseMessage> SendAsync(string? authorization, bool enableServerAuthorization = false)
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(builder => ConfigureWebHost(builder, enableServerAuthorization)).StartAsync();
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
    /// Computes a valid Hawk Authorization header for the given values.
    /// </summary>
    private static string ComputeAuthorization(long timestamp, string nonce, string? hash = null,
        string method = "GET", string resource = "/api/TodoItems/1")
    {
        var crypto = new DefaultCryptoFactory().Create(Credential.HmacAlgorithm, Credential.HashAlgorithm, Credential.AuthKey);
        var hawkData = new HawkData
        {
            Timestamp = timestamp,
            Nonce = nonce,
            Method = method,
            Resource = resource,
            Host = "example.com",
            Port = 80,
            Hash = hash
        };
        var mac = crypto.CalculateRequestMac(hawkData);
        return $"Hawk id=\"{Credential.AuthId}\", ts=\"{timestamp}\", nonce=\"{nonce}\", mac=\"{mac}\""
             + (hash == null ? "" : $", hash=\"{hash}\"");
    }

    [Fact]
    public async Task MissingAuthorizationHeader_Returns401()
    {
        var response = await SendAsync(null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Missing Authorization header.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task BadMac_Returns401()
    {
        var authorization = $"Hawk id=\"id123\", ts=\"{NowSeconds()}\", nonce=\"{Guid.NewGuid():N}\", mac=\"AAAABBBBCCCC\"";
        var response = await SendAsync(authorization);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bad mac.", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task StaleTimestamp_Returns401WithServerTimestamp()
    {
        var staleTimestamp = NowSeconds() - 3600; // far outside the 300s default skew
        var authorization = $"Hawk id=\"id123\", ts=\"{staleTimestamp}\", nonce=\"{Guid.NewGuid():N}\", mac=\"AAAA\"";
        var response = await SendAsync(authorization);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = response.Headers.WwwAuthenticate.ToString();
        Assert.Contains("Stale timestamp.", challenge);
        Assert.Contains("ts=\"", challenge);  // server timestamp for clock synchronization
        Assert.Contains("tsm=\"", challenge); // timestamp mac
    }

    [Fact]
    public async Task BadPayloadHash_Returns401()
    {
        // the mac is valid for hash "abcdef", but the actual body hashes differently
        var timestamp = NowSeconds();
        var nonce = Guid.NewGuid().ToString("N");
        var authorization = ComputeAuthorization(timestamp, nonce, "abcdef", "POST", "/api/TodoItems");

        using var host = await new HostBuilder()
            .ConfigureWebHost(builder => ConfigureWebHost(builder)).StartAsync();
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
        var authorization = ComputeAuthorization(NowSeconds(), Guid.NewGuid().ToString("N"));

        using var host = await new HostBuilder()
            .ConfigureWebHost(builder => ConfigureWebHost(builder)).StartAsync();
        using var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://example.com");
        using var client = server.CreateClient();

        using var first = new HttpRequestMessage(HttpMethod.Get, "api/TodoItems/1");
        first.Headers.TryAddWithoutValidation("Authorization", authorization);
        var firstResponse = await client.SendAsync(first);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode); // authenticated

        using var second = new HttpRequestMessage(HttpMethod.Get, "api/TodoItems/1");
        second.Headers.TryAddWithoutValidation("Authorization", authorization);
        var secondResponse = await client.SendAsync(second);
        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
        Assert.Contains("Replay request.", secondResponse.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task UnauthenticatedRequest_WithServerAuthorizationEnabled_NoServerAuthorizationHeader()
    {
        // regression guard: HawkMiddleware must pass unauthenticated requests through
        // without buffering the response
        var response = await SendAsync(null, enableServerAuthorization: true);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Server-Authorization"));
    }
}
