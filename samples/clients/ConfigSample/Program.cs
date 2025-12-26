using Alastack.HmacAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sample.Common;

namespace ConfigSample
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var host = CreateHawkAuthenticationHost(new Uri("https://localhost:5001/"));

            var apiClient = host.Services.GetRequiredService<ApiClient>();
            await ApiInvoke(apiClient);

            Console.ReadKey();
        }

        static IHost CreateHawkAuthenticationHost(Uri serverAddress)
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
                    //    options.GetSpecificData = async (request, options) => await Task.FromResult("some-data");
                    //});
                    services.AddSingleton<IValidateOptions<HawkSettings>, HawkSettingsValidation>();
                    services.AddTransient<HawkDelegatingHandler>();
                    services.AddHttpClient<ApiClient>("ApiClient", httpClient => httpClient.BaseAddress = serverAddress)
                    .AddHttpMessageHandler<HawkDelegatingHandler>();
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
}