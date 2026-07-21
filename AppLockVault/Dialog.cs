using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace AppLockVault;

/// <summary>
/// A small themed modal dialog. Avalonia has no built-in message box, so this builds one that
/// inherits the app's dark theme (its buttons pick up the global "primary"/base Button styles).
/// </summary>
public static class Dialog
{
    public static Task Info(Window owner, string title, string message)
        => ShowCore(owner, title, message, "#8B6DFF", "OK", null);

    public static Task Error(Window owner, string title, string message)
        => ShowCore(owner, title, message, "#FF6B6B", "OK", null);

    public static async Task<bool> Confirm(Window owner, string title, string message)
        => await ShowCore(owner, title, message, "#F5C451", "Yes", "No") == true;

    private static async Task<bool?> ShowCore(
        Window owner, string title, string message, string accentHex, string primaryText, string? secondaryText)
    {
        var dlg = new Window
        {
            Title = title,
            Width = 400,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = new SolidColorBrush(Color.Parse("#14161E"))
        };

        var titleBlock = new TextBlock
        {
            Text = title,
            FontSize = 16,
            FontWeight = FontWeight.SemiBold,
            Foreground = new SolidColorBrush(Color.Parse(accentHex)),
            TextWrapping = TextWrapping.Wrap
        };

        var messageBlock = new TextBlock
        {
            Text = message,
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.Parse("#C4C9D6")),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 10, 0, 18)
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 10
        };

        if (secondaryText is not null)
        {
            var secondary = new Button { Content = secondaryText, MinWidth = 84 };
            secondary.Click += (_, _) => dlg.Close(false);
            buttons.Children.Add(secondary);
        }

        var primary = new Button { Content = primaryText, MinWidth = 84 };
        primary.Classes.Add("primary");
        primary.Click += (_, _) => dlg.Close(true);
        buttons.Children.Add(primary);

        dlg.Content = new Border
        {
            Padding = new Thickness(22),
            Child = new StackPanel { Children = { titleBlock, messageBlock, buttons } }
        };

        return await dlg.ShowDialog<bool?>(owner);
    }
}
