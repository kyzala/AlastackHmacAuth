namespace Sample.Common;

/// <summary>
/// Console output helpers for <see cref="TodoItem"/> collections.
/// </summary>
public static class TodoItemConsole
{
    public static void Print(IEnumerable<TodoItem>? items)
    {
        if (items == null)
        {
            Console.WriteLine("(null)");
            return;
        }
        foreach (var item in items)
        {
            Print(item);
        }
    }

    public static void Print(TodoItem? item)
    {
        Console.WriteLine(item == null ? "(null)" : $"{item.Id}\t{item.Name}\t{item.IsComplete}");
    }
}
