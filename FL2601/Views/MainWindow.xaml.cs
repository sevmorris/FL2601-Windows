using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using FL2601.ViewModels;

namespace FL2601.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // The panel's natural height exceeds a 1080p screen once Windows is
        // scaling, and a window taller than the desktop opens with its title
        // bar off the top. Cap it at the work area and let the ScrollViewer
        // take up the difference.
        Height = Math.Min(Height, SystemParameters.WorkArea.Height - 40);

        if (DataContext is CipherViewModel vm)
        {
            vm.PassphrasesClearRequested += ClearPassphraseBoxes;
            vm.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void PassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is CipherViewModel vm)
            vm.Passphrase = ((PasswordBox)sender).Password;
    }

    private void ConfirmPassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is CipherViewModel vm)
            vm.ConfirmPassphrase = ((PasswordBox)sender).Password;
    }

    private void ClearPassphraseBoxes()
    {
        PassphraseBox.Clear();
        ConfirmPassphraseBox.Clear();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // Keep the confirm box in sync when a mode switch clears the property.
        if (e.PropertyName == nameof(CipherViewModel.ConfirmPassphrase)
            && DataContext is CipherViewModel vm
            && vm.ConfirmPassphrase.Length == 0
            && ConfirmPassphraseBox.Password.Length > 0)
        {
            ConfirmPassphraseBox.Clear();
        }
    }

    /// <summary>
    /// Handled on the tunnelling route rather than through
    /// <c>Window.InputBindings</c>: the focused text box would otherwise consume
    /// the keystroke before it bubbled this far, and these shortcuts are most
    /// useful precisely while typing.
    /// </summary>
    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        base.OnPreviewKeyDown(e);
        if (e.Handled || DataContext is not CipherViewModel vm) return;
        if ((Keyboard.Modifiers & ModifierKeys.Control) != ModifierKeys.Control) return;

        bool shift = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift;

        switch (e.Key)
        {
            // Ctrl+Enter runs the current mode.
            case Key.Enter when !shift && vm.ProcessCommand.CanExecute(null):
                vm.ProcessCommand.Execute(null);
                e.Handled = true;
                break;

            // Ctrl+L clears, following the terminal convention. Ctrl+Delete —
            // the Mac build's shortcut — is taken by delete-word-forward in a
            // text field.
            case Key.L when !shift:
                vm.ClearCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.C when shift && vm.CopyCommand.CanExecute(null):
                vm.CopyCommand.Execute(null);
                e.Handled = true;
                break;
        }
    }
}
