using Spectre.Console;

namespace TizenAppInstallerCli;

public static class FilePicker
{
    /// <summary>
    /// Interactive file picker using Spectre.Console.
    /// Returns full path or null if cancelled.
    /// </summary>
    public static string? PickFile(
        string? initialDirectory = null,
        string[]? allowedExtensions = null,
        bool showHidden = false,
        bool clearBeforePrompt = false)
    {
        string current = (initialDirectory != null && Directory.Exists(initialDirectory))
            ? Path.GetFullPath(initialDirectory)
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        while (true)
        {
            List<FileSystemItem> items = [];

            DirectoryInfo? parent = Directory.GetParent(current);
            if (parent != null)
                items.Add(FileSystemItem.Action(".. (Parent)", parent.FullName, isDirectory: true));

            IEnumerable<string> dirs;
            IEnumerable<string> files;
            try
            {
                dirs = Directory.EnumerateDirectories(current)
                    .Where(d => showHidden || !IsHidden(d));
                files = Directory.EnumerateFiles(current)
                    .Where(f => showHidden || !IsHidden(f))
                    .Where(f => IsAllowed(f, allowedExtensions));
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
                current = parent?.FullName ?? current;
                continue;
            }

            List<FileSystemItem> dirItems = dirs
                .Select(d => FileSystemItem.Directory(Path.GetFileName(d) ?? d, d))
                .OrderBy(d => d.Display)
                .ToList();

            List<FileSystemItem> fileItems = files
                .Select(f => FileSystemItem.File(Path.GetFileName(f) ?? f, f))
                .OrderBy(f => f.Display)
                .ToList();

            items.AddRange(dirItems);
            items.AddRange(fileItems);

            // Actions
            items.Add(FileSystemItem.Action("Enter path manually", null));
            items.Add(FileSystemItem.Action("Cancel", null));

            int terminalHeight = GetTerminalHeight();
            // leave a small margin for the title / footer / prompt lines:
            int calculatedPageSize = Math.Max(3, terminalHeight - 6);
            int pageSize = Math.Min(calculatedPageSize, Math.Max(3, items.Count));

            if (clearBeforePrompt)
                AnsiConsole.Clear();

            SelectionPrompt<FileSystemItem> prompt = new SelectionPrompt<FileSystemItem>()
                .Title($"Current directory [green]{current}[/]")
                .PageSize(pageSize)
                .MoreChoicesText("[grey](Use arrows / page up/down)[/]")
                .UseConverter(item => item.GetMarkup());

            FileSystemItem choice = AnsiConsole.Prompt(prompt.AddChoices(items));

            if (choice.IsAction)
            {
                if (choice.Display.StartsWith("Enter path"))
                {
                    var path = AnsiConsole.Ask<string>("Full path to file:");
                    if (File.Exists(path) && IsAllowed(path, allowedExtensions))
                        return Path.GetFullPath(path);

                    AnsiConsole.MarkupLine("[red]Invalid file path or extension.[/]");
                    continue;
                }

                if (choice.Display.StartsWith("Cancel"))
                    return null;
            }

            if (choice.IsDirectory)
            {
                current = choice.FullPath ?? current;
                continue;
            }

            return choice.FullPath;
        }
    }

    private static int GetTerminalHeight()
    {
        try
        {
            // Console.WindowHeight can throw if output is redirected or not a TTY.
            int h = Console.WindowHeight;
            return h > 0 ? h : 25;
        }
        catch
        {
            // Fallback when no interactive terminal; choose a reasonable default
            return 25;
        }
    }

    private sealed class FileSystemItem
    {
        public string Display { get; }
        public string? FullPath { get; }
        public bool IsDirectory { get; }
        public bool IsAction { get; }

        private FileSystemItem(string display, string? fullPath, bool isDirectory, bool isAction)
        {
            Display = display;
            FullPath = fullPath;
            IsDirectory = isDirectory;
            IsAction = isAction;
        }

        public static FileSystemItem Directory(string name, string fullPath) =>
            new FileSystemItem($"[blue]{name}/[/]", fullPath, true, false);

        public static FileSystemItem File(string name, string fullPath)
        {
            var info = new FileInfo(fullPath);
            string size = info.Length >= 1024 ? $"{info.Length / 1024} KB" : $"{info.Length} B";
            var modified = info.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm");
            return new FileSystemItem($"{name} — {size} • {modified}", fullPath, false, false);
        }

        public static FileSystemItem Action(string name, string? fullPath, bool isDirectory = false) =>
            new FileSystemItem(name, fullPath, isDirectory, true);

        public string GetMarkup() => Display;
    }

    private static bool IsHidden(string path)
    {
        try
        {
            FileAttributes attr = File.GetAttributes(path);
            return (attr & FileAttributes.Hidden) != 0 || (attr & FileAttributes.System) != 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAllowed(string filePath, string[]? allowed)
    {
        if (allowed == null || allowed.Length == 0) return true;
        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        return allowed.Any(a =>
        {
            string norm = a.StartsWith("*.") ? a.Substring(1) : a.StartsWith(".") ? a : "." + a;
            return ext == norm.ToLowerInvariant();
        });
    }
}