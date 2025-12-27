using Alastack.HmacAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using Sample.Common;
using System.Text;
using Xunit.Abstractions;
using static System.Net.Mime.MediaTypeNames;

namespace Alastack.HmacAuth.Tests;

public class HmacClientTests
{
    private readonly ITestOutputHelper _outputHelper;

    public HmacClientTests(ITestOutputHelper outputHelper)
    {
        _outputHelper = outputHelper;
    }

    [Theory]
    [InlineData("Hmac id123:1662118565:abcdef:fDsO2Fhqs4wlQbdlQEUiz0zkv+257n1SwN76jDjy7lk=:megVFcCd4uYcboNPG8BqzQ==")]
    public async Task SendAsync_HmacClient_ValidateAuthenticationHeaderIncludePayloadHash(string expected)
    {
        Action<HmacSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = true;
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
    [InlineData("Hmac id123:1662118565:abcdef:3ru7ibxtMinMNvfDTm9R+b86gKg7rn20DfzUOkCOgpA=:")]
    public async Task SendAsync_HmacClient_ValidateAuthenticationHeaderExcludePayloadHash(string expected)
    {
        Action<HmacSettings> configureOptions = options =>
        {
            options.IncludePayloadHash = false;
        };
        var httpClient = CreateClient(configureOptions);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://a.b.c:5000/api/q?a=1&b=2");

        var response = await httpClient.SendAsync(request);
        var authStr = request.Headers.Authorization!.ToString();
        _outputHelper.WriteLine(authStr);
        Assert.Equal(expected, request.Headers.Authorization.ToString());
    }

    private static HttpClient CreateClient(Action<HmacSettings> configureOptions)
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
                services.Configure<HmacSettings>(options =>
                {
                    options.AppId = "id123";
                    options.AppKey = "3@uo45er?";
                    options.TimeOffset = 0;
                    options.TimestampCalculator = stubTimestampCalculator.Object;
                    options.NonceGenerator = stubNonceGenerator.Object;
                });
                services.Configure(configureOptions);
                services.AddTransient<InjectableHmacDelegatingHandler>();
                services.AddTransient<TestHmacDelegatingHandler>();
                services.AddHttpClient("ApiClient")
                    .AddHttpMessageHandler<InjectableHmacDelegatingHandler>()
                    .AddHttpMessageHandler<TestHmacDelegatingHandler>();
            })
            .Build();

        return host.Services.GetRequiredService<IHttpClientFactory>().CreateClient("ApiClient");
    }
}