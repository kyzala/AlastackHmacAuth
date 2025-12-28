using Alastack.HmacAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sample.Common;

namespace ClientHostSample;

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
            var host1 = CreateHmacAuthClientHost(new Uri("https://localhost:5001/"));
            var apiClient1 = host1.Services.GetRequiredService<ApiClient>();
            await ApiInvoke(apiClient1);
        }
        else
        {
            Console.WriteLine("\n=> Test hawk auth ...\n");
            var host2 = CreateHawkAuthClientHost(new Uri("https://localhost:5001/"));
            var apiClient2 = host2.Services.GetRequiredService<ApiClient>();
            await ApiInvoke(apiClient2);
        }

        Console.WriteLine("\n=> Test completed\n");
        Console.ReadKey();
    }

    static IHost CreateHmacAuthClientHost(Uri serverAddress)
    {
        return new HostBuilder()
            .ConfigureServices(services =>
            {
                services.Configure<HmacSettings>(options =>
                {
                    options.AppId = appId;
                    options.AppKey = appKey;
                });
                services.AddSingleton<IValidateOptions<HmacSettings>, HmacConfigValidation>();
                services.AddTransient<InjectableHmacDelegatingHandler>();
                services.AddHttpClient<ApiClient>("ApiClient", httpClient =>
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
            .ConfigureAppConfiguration(config =>
            {
                config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            })
            //.UseDefaultServiceProvider(options => options.ValidateScopes = true)
            .ConfigureServices((context, services) =>
            {
                services.Configure<HawkSettings>(context.Configuration.GetSection("HawkSettings"));
                //services.Configure<HawkSettings>(options =>
                //{
                //    options.AuthId = "id123";
                //    options.AuthKey = "3@uo45er?";
                //    options.App = "app1234";
                //    options.Dlg = "dlg1234";
                //    options.EnableServerAuthorizationValidation = true;
                //    options.GetSpecificData = async (request, options) => await Task.FromResult("some-data");
                //});
                services.AddSingleton<IValidateOptions<HawkSettings>, HawkConfigValidation>();
                services.AddTransient<InjectableHawkDelegatingHandler>();
                services.AddHttpClient<ApiClient>("ApiClient", httpClient =>
                {
                    httpClient.BaseAddress = serverAddress;
                    httpClient.DefaultRequestVersion = new Version(2, 0);
                })
                .AddHttpMessageHandler<InjectableHawkDelegatingHandler>();
            })
            .Build();
    }

    static async Task ApiInvoke(ApiClient apiClient)
    {
        await apiClient.CreateTodoItemAsync(new TodoItem { Name = "walk dog", IsComplete = true });
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