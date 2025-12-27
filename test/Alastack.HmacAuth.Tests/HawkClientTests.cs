using Alastack.HmacAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Sample.Common;
using System.Net;
using System.Text;
using Xunit.Abstractions;
using static System.Net.Mime.MediaTypeNames;

namespace Alastack.HmacAuth.Tests;

public class HawkClientTests
{
    private readonly ITestOutputHelper _outputHelper;

    public HawkClientTests(ITestOutputHelper outputHelper)
    {
        _outputHelper = outputHelper;
    }

    [Theory]
    [InlineData(null, null, null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", mac=\"QMbhfMP+kUiixTSTSa9ALmc/bL4iT725p62/Dnck4mM=\"")]
    [InlineData("extdata", null, null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"kCVNXF0ki+2AcM8gf0BE3m7ShsvAghExAKjh2qMIjjc=\"")]
    [InlineData("extdata", "abc", null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"cNX1z5hywwV4Zeoejp81APyxPGvAst8zDbjy8uiK2f4=\", app=\"abc\", dlg=\"\"")]
    [InlineData("extdata", "abc", "123",
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"O4MnqtWlnXVgS4QJNuVf2iB4XiV6uGlGIi0eU9eSrUA=\", app=\"abc\", dlg=\"123\"")]
    public async Task SendAsync_HawkClient_ValidateAuthenticationHeaderIncludePayloadHash(string? ext, string? app, string? dlg, string expected)
    {
        Action<HawkSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = true;
            options.App = app;
            options.Dlg = dlg;
            options.GetSpecificData = async (request, options) => await Task.FromResult(ext);
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Post, "http://a.b.c:5000/api/data")
        {
            Content = new StringContent("{\"name\":\"value\"}", Encoding.UTF8, Application.Json)
        };

        var response = await httpClient.SendAsync(request);
        var authStr = request.Headers.Authorization!.ToString();
        _outputHelper.WriteLine(authStr);
        Assert.Equal("application/json", request.Content.Headers.ContentType!.MediaType);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(expected, request.Headers.Authorization.ToString());
    }

    [Theory]
    [InlineData(null, null, null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", mac=\"PrW3nCv0sln6lOEYEKiKFO0Xr9FrtT4lY7ZfgO+uK+4=\"")]
    [InlineData("extdata", null, null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"jFFBjfNU18hdXCIeB/EQ+xe3ZhL0qF5ZsD+kjVMlxh0=\"")]
    [InlineData("extdata", "abc", null,
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"QzHSDcM4mGppdrIKF5GAF/0vqJ05EC2Jw66R4C7rldg=\", app=\"abc\", dlg=\"\"")]
    [InlineData("extdata", "abc", "123",
        "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"ur1ZDiYXrFtrG80WS3WJI7Kz2aBl9egyD6ZEasQxCD8=\", app=\"abc\", dlg=\"123\"")]
    public async Task SendAsync_HawkClient_ValidateAuthenticationHeaderExcludePayloadHash(string? ext, string? app, string? dlg, string expected)
    {
        Action<HawkSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = false;
            options.App = app;
            options.Dlg = dlg;
            options.GetSpecificData = async (request, options) => await Task.FromResult(ext);
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://a.b.c:5000/api/q?a=1&b=2");

        var response = await httpClient.SendAsync(request);
        var authStr = request.Headers.Authorization!.ToString();
        _outputHelper.WriteLine(authStr);
        Assert.Equal(expected, request.Headers.Authorization.ToString());
    }

    [Fact]
    public async Task SendAsync_HawkClient_ValidateServerAuthorizationSuccess()
    {
        Action<HawkSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = true;
            options.App = "abc";
            options.Dlg = "123";
            options.EnableServerAuthorizationValidation = true;
            options.EnableServerTimeValidation = false;
            options.GetSpecificData = async (request, options) => await Task.FromResult("extdata");
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Post, "http://a.b.c:5000/api/data")
        {
            Content = new StringContent("{\"name\":\"value\"}", Encoding.UTF8, Application.Json)
        };

        var response = await httpClient.SendAsync(request);
        var authStr = request.Headers.Authorization!.ToString();
        _outputHelper.WriteLine(authStr);

        response.Headers.TryGetValues("Server-Authorization", out var authorizations);
        var authorization = authorizations!.FirstOrDefault();
        _outputHelper.WriteLine(authorization);

        Assert.Equal("application/json", request.Content.Headers.ContentType!.MediaType);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("Hawk mac=\"+pqdXC3Mq8yNc9PBF8KemEykJM8171m5Z6nvI2OxUBM=\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\"", authorization);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task SendAsync_HawkClient_ValidateServerAuthorizationFailure()
    {
        Action<HawkSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = true;
            options.App = "abc";
            options.Dlg = "123";
            options.EnableServerAuthorizationValidation = true;
            options.EnableServerTimeValidation = false;
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Put, "http://a.b.c:5000/api/data/1")
        {
            Content = new StringContent("{\"name\":\"value\"}", Encoding.UTF8, Application.Json)
        };

        var response = await httpClient.SendAsync(request);
        var authStr = request.Headers.Authorization!.ToString();
        _outputHelper.WriteLine(authStr);

        response.Headers.TryGetValues("Server-Authorization", out var authorizations);
        var authorization = authorizations!.FirstOrDefault();
        _outputHelper.WriteLine(authorization);

        Assert.Equal("application/json", request.Content.Headers.ContentType!.MediaType);
        Assert.Equal("application/json", response.Content.Headers.ContentType!.MediaType);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void SendAsync_HawkClient_ValidateServerTimestampException()
    {
        Action<HawkSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = true;
            options.App = "abc";
            options.Dlg = "123";
            options.EnableServerAuthorizationValidation = false;
            options.EnableServerTimeValidation = true;
            options.GetSpecificData = async (request, options) => await Task.FromResult("extdata");
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Delete, "http://a.b.c:5000/api/data/1");
        Assert.Throws<AggregateException>(() => httpClient.SendAsync(request).Result);
    }

    private static HttpClient CreateClient(Action<HawkSettings> configureOptions)
    {
        var stubTimestampCalculator = new Mock<ITimestampCalculator>();
        stubTimestampCalculator.Setup(tc => tc.Calculate(0)).Returns(1662118565);

        var stubNonceGenerator = new Mock<INonceGenerator>();
        stubNonceGenerator.Setup(ng => ng.Generate("id123")).Returns("abcdef");

        //var stubHandler = new Mock<HttpMessageHandler>();
        //stubHandler.Protected()
        //           .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(),
        //        ItExpr.IsAny<CancellationToken>())
        //           .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var host = new HostBuilder()
            .ConfigureServices(services =>
            {
                services.Configure<HawkSettings>(options =>
                {
                    options.AuthId = "id123";
                    options.AuthKey = "3@uo45er?";
                    options.TimeOffset = 0;
                    options.TimestampCalculator = stubTimestampCalculator.Object;
                    options.NonceGenerator = stubNonceGenerator.Object;
                });
                services.Configure(configureOptions);
                services.AddTransient<InjectableHawkDelegatingHandler>();
                services.AddTransient<TestHawkDelegatingHandler>();
                services.AddHttpClient("ApiClient")
                    .AddHttpMessageHandler<InjectableHawkDelegatingHandler>()
                    .AddHttpMessageHandler<TestHawkDelegatingHandler>();
            })
            .Build();

        return host.Services.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient");
    }
}