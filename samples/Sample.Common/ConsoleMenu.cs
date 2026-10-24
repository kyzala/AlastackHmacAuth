namespace Sample.Common;

/// <summary>
/// Minimal interactive console menu for the sample clients.
/// </summary>
public static class ConsoleMenu
{
    public sealed record Item(string Label, Func<Task> Action);

    /// <summary>
    /// Single-choice prompt. Returns the zero-based option index.
    /// </summary>
    public static int Pick(string title, IReadOnlyList<string> options)
    {
        Console.WriteLine($"== {title} ==");
        for (var i = 0; i < options.Count; i++)
        {
            Console.WriteLine($"  [{i + 1}] {options[i]}");
        }
        while (true)
        {
            Console.Write("Your choice: ");
            var input = Console.ReadLine()?.Trim();
            if (int.TryParse(input, out var index) && index >= 1 && index <= options.Count)
            {
                return index - 1;
            }
            Console.WriteLine("Invalid choice.");
        }
    }

    /// <summary>
    /// Runs an interactive menu loop until the user enters "q".
    /// </summary>
    public static async Task RunAsync(string title, IReadOnlyList<Item> items)
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine($"== {title} ==");
            for (var i = 0; i < items.Count; i++)
            {
                Console.WriteLine($"  [{i + 1}] {items[i].Label}");
            }
            Console.WriteLine("  [q] Quit");
            Console.Write("Your choice: ");

            var input = Console.ReadLine()?.Trim();
            if (string.Equals(input, "q", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            if (int.TryParse(input, out var index) && index >= 1 && index <= items.Count)
            {
                try
                {
                    await items[index - 1].Action();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Invalid choice.");
            }
        }
    }

    /// <summary>
    /// Prompts for a value; returns <paramref name="defaultValue"/> when empty.
    /// </summary>
    public static string ReadString(string prompt, string defaultValue)
    {
        Console.Write($"{prompt} [{defaultValue}]: ");
        var input = Console.ReadLine()?.Trim();
        return string.IsNullOrEmpty(input) ? defaultValue : input;
    }

    /// <summary>
    /// Prompts for a positive integer; returns <paramref name="defaultValue"/> when empty or invalid.
    /// </summary>
    public static long ReadLong(string prompt, long defaultValue)
    {
        Console.Write($"{prompt} [{defaultValue}]: ");
        var input = Console.ReadLine()?.Trim();
        return long.TryParse(input, out var value) && value > 0 ? value : defaultValue;
    }
}
