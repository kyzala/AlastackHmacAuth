using Alastack.HmacAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Refit;
using Sample.Common;

namespace RefitSample;

internal class Program
{
    const string appId = "id123";
    const string appKey = "3@uo45er?";

    static async Task Main(string[] args)
    {
        Console.WriteLine("Please choose authentication type:");
        Console.WriteLine("(1) HMAC authentication - Press [M] key");
        Console.WriteLine("(2) Hawk authentication - Press any other key");
        Console.Write("Your choice: ");
        if (Console.ReadKey().Key == ConsoleKey.M)
        {
            Console.WriteLine("\n=> Test hmac auth ...\n");
            var host1 = CreateHmacAuthClientHost(new Uri("https://localhost:1080/"));
            var apiClient1 = host1.Services.GetRequiredService<IApiClient>();
            await ApiInvoke(apiClient1);
        }
        else
        {
            Console.WriteLine("\n=> Test hawk auth ...\n");
            var host2 = CreateHawkAuthClientHost(new Uri("http://192.168.1.102:2080/"));
            var apiClient2 = host2.Services.GetRequiredService<IApiClient>();
            await ApiInvoke(apiClient2);
        }

        Console.WriteLine("\n=> Test completed\n");
        Console.ReadKey();
    }

    static IHost CreateHmacAuthClientHost(Uri serverAddress)
    {
        return new HostBuilder()
            //.UseDefaultServiceProvider(options => options.ValidateScopes = true)
            .ConfigureServices(services =>
            {
                services.Configure<HmacSettings>(options =>
                {
                    options.AppId = appId;
                    options.AppKey = appKey;
                });
                services.AddSingleton<IValidateOptions<HmacSettings>, HmacConfigValidation>();
                services.AddTransient<InjectableHmacDelegatingHandler>();
                services.AddRefitClient<IApiClient>().ConfigureHttpClient(httpClient =>
                {
                    httpClient.BaseAddress = serverAddress;
                    httpClient.DefaultRequestVersion = new Version(2, 0);
                })
                .AddHttpMessageHandler<InjectableHmacDelegatingHandler>();
            })
            .Build();
    }

    static IHost CreateHawkAuthClientHost(Uri serverAddress)
    {
        return new HostBuilder()
            .UseDefaultServiceProvider(options => options.ValidateScopes = true)
            .ConfigureServices(services =>
            {
                services.Configure<HawkSettings>(options =>
                {
                    options.AuthId = appId;
                    options.AuthKey = appKey;
                    options.App = "app1234";
                    options.Dlg = "dlg1234";
                    options.EnableServerAuthorizationValidation = true;
                    options.GetSpecificData = async (request, options) => await Task.FromResult("some-data");
                });
                services.AddSingleton<IValidateOptions<HawkSettings>, HawkConfigValidation>();
                services.AddTransient<InjectableHawkDelegatingHandler>();
                services.AddRefitClient<IApiClient>().ConfigureHttpClient(httpClient => httpClient.BaseAddress = serverAddress)
                .AddHttpMessageHandler<InjectableHawkDelegatingHandler>();
            })
            .Build();
    }

    static async Task ApiInvoke(IApiClient apiClient)
    {
        Console.WriteLine((await apiClient.DebugForwardedAsync()).ToString());

        await apiClient.CreateTodoItemAsync(new TodoItem { Id = 1, Name = "walk dog", IsComplete = true });
        await apiClient.UpdateTodoItemAsync(new TodoItem { Id = 1, Name = "feed fish", IsComplete = true });
        Print(await apiClient.GetTodoItemsAsync());
        Print(await apiClient.GetTodoItemAsync(1));
        await apiClient.DeleteTodoItemAsync(1);
    }

    static void Print(IEnumerable<TodoItem>? items)
    {
        if (items != null)
        {
            foreach (var item in items)
            {
                Print(item);
            }
        }
    }

    static void Print(TodoItem? item)
    {
        if (item != null)
        {
            Console.WriteLine($"{item.Id}\t{item.Name}\t{item.IsComplete}");
        }
    }
}