using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text;

namespace Alastack.HmacAuth.Tests;

public class HmacMiddlewareTests
{
    [Theory]
    [InlineData("Hmac id123:1662118565:abcdef:SXbE34WOCepEWy1iyAUfGNWykPiX8uIQtC8b5OXewzI=:rh/Kd6geqLVo72DNrR3ua64fqvcWzdyi9XULfNybbtQ=")]
    public async Task HandleAuthenticateAsync_HmacHandler_ValidateIncludePayloadHash(string authHeaderValue)
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(ConfigureWebHost)
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Headers.Authorization = authHeaderValue;
            c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/data";
            c.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"value\"}"));
            c.Response.ContentType = "application/json";
            c.Response.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"result\":\"value\"}"));
        });

        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Hmac", context.User.Identity!.AuthenticationType);
        Assert.Equal(TestConstants.AppId, context.User.Claims.FirstOrDefault()!.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("Hmac id123:1662118565:abcdef:3ru7ibxtMinMNvfDTm9R+b86gKg7rn20DfzUOkCOgpA=:")]
    public async Task HandleAuthenticateAsync_HmacHandler_ValidateExcludePayloadHash(string authHeaderValue)
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(ConfigureWebHost)
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Headers.Authorization = authHeaderValue;
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/q";
            c.Request.QueryString = new QueryString("?a=1&b=2");
        });

        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Hmac", context.User.Identity!.AuthenticationType);
        Assert.Equal(TestConstants.AppId, context.User.Claims.FirstOrDefault()!.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    private static void ConfigureWebHost(IWebHostBuilder webBuilder)
    {
        webBuilder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddMemoryCache();
                services.AddRouting();
                services.AddAuthorization();
                services.AddAuthentication(options =>
                {
                    options.DefaultScheme = HmacDefaults.AuthenticationScheme;
                })
                .AddHmac(options =>
                {
                    var credential = new HmacCredential
                    {
                        AppId = TestConstants.AppId,
                        AppKey = TestConstants.AppKey
                    };
                    options.RequireTimeSkewValidation = false;
                    var dict = new Dictionary<string, HmacCredential> { { TestConstants.AppId, credential } };
                    options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(dict);
                });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
            });
    }
}
