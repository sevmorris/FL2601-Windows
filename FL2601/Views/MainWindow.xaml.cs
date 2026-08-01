using System.Windows;
using System.Windows.Controls;
using FL2601.ViewModels;

namespace FL2601.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    // PasswordBox doesn't support binding, so we use code-behind events
    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is CipherViewModel vm)
            vm.Password = ((PasswordBox)sender).Password;
    }

    private void ConfirmPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is CipherViewModel vm)
            vm.ConfirmPassword = ((PasswordBox)sender).Password;
    }
}
