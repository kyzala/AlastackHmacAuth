using Alastack.HmacAuth;
using Sample.Common;

// Raw HttpClient sample: no DI container. Pick a scenario from the menu;
// each scenario creates an auth handler with the shared sample credentials.

await ConsoleMenu.RunAsync("ClientBasicSample (raw HttpClient)", new ConsoleMenu.Item[]
{
    new("Hmac - GET /WeatherForecast",
        () => GetWeatherForecastAsync(new HmacDelegatingHandler(SampleCredentials.AppId, SampleCredentials.AppKey))),
    new("Hawk - GET /WeatherForecast",
        () => GetWeatherForecastAsync(new HawkDelegatingHandler(SampleCredentials.AppId, SampleCredentials.AppKey))),
    new("Hmac - concurrency burst (20 parallel GETs)",
        () => WeatherForecastBurstAsync(new HmacDelegatingHandler(SampleCredentials.AppId, SampleCredentials.AppKey))),
    new("Hawk - concurrency burst (20 parallel GETs)",
        () => WeatherForecastBurstAsync(new HawkDelegatingHandler(SampleCredentials.AppId, SampleCredentials.AppKey))),
});

static HttpClient CreateClient(DelegatingHandler authHandler)
{
    authHandler.InnerHandler = SampleHttp.CreateDevHandler();
    return new HttpClient(authHandler)
    {
        BaseAddress = new Uri(ConsoleMenu.ReadString("Base address", SampleCredentials.DefaultBaseAddress))
    };
}

static async Task GetWeatherForecastAsync(DelegatingHandler authHandler)
{
    using var client = CreateClient(authHandler);
    Console.WriteLine(await client.GetStringAsync("/WeatherForecast"));
}

static async Task WeatherForecastBurstAsync(DelegatingHandler authHandler)
{
    using var client = CreateClient(authHandler);
    var tasks = Enumerable.Range(1, 20).Select(_ => client.GetStringAsync("/WeatherForecast"));
    var results = await Task.WhenAll(tasks);
    Console.WriteLine($"{results.Length} requests succeeded.");
}
