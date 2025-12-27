using Sample.Common;
using System.Text;
using System.Text.Json;
using static System.Net.Mime.MediaTypeNames;

namespace ConfigSample
{
    public sealed class ApiClient
    {
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonSerializerOptions;

        public ApiClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _jsonSerializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        }

        public async Task<IEnumerable<TodoItem>?> GetTodoItemsAsync()
        {
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "/api/TodoItems")
            {
                Version = new Version(2, 0)
            };
            var httpResponseMessage = await _httpClient.SendAsync(httpRequestMessage, HttpCompletionOption.ResponseHeadersRead);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                using var contentStream = await httpResponseMessage.Content.ReadAsStreamAsync();
                //var resut = await httpResponseMessage.Content.ReadAsStringAsync();
                return await JsonSerializer.DeserializeAsync<IEnumerable<TodoItem>>(contentStream, _jsonSerializerOptions);
            }
            return null;
        }

        public async Task<TodoItem?> GetTodoItemAsync(long id)
        {
            var httpResponseMessage = await _httpClient.GetAsync($"/api/TodoItems/{id}");
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                using var contentStream = await httpResponseMessage.Content.ReadAsStreamAsync();
                var resut = await httpResponseMessage.Content.ReadAsStringAsync();
                return await JsonSerializer.DeserializeAsync<TodoItem>(contentStream, _jsonSerializerOptions);
            }
            return null;
        }

        public async Task CreateTodoItemAsync(TodoItem todoItem)
        {
            var todoItemJson = new StringContent(JsonSerializer.Serialize(todoItem), Encoding.UTF8, Application.Json);
            using var httpResponseMessage = await _httpClient.PostAsync("/api/TodoItems", todoItemJson);

            //httpResponseMessage.EnsureSuccessStatusCode();
        }

        public async Task UpdateTodoItemAsync(TodoItem todoItem)
        {
            var todoItemJson = new StringContent(JsonSerializer.Serialize(todoItem), Encoding.UTF8, Application.Json);
            using var httpResponseMessage = await _httpClient.PutAsync($"/api/TodoItems/{todoItem.Id}", todoItemJson);

            //httpResponseMessage.EnsureSuccessStatusCode();
        }

        public async Task DeleteTodoItemAsync(long id)
        {
            using var httpResponseMessage = await _httpClient.DeleteAsync($"/api/TodoItems/{id}");

            //httpResponseMessage.EnsureSuccessStatusCode();
        }
    }
}