using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using FL2601.ViewModels;

namespace FL2601.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        if (DataContext is CipherViewModel vm)
        {
            vm.PasswordsClearRequested += ClearPasswordBoxes;
            vm.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

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

    private void ClearPasswordBoxes()
    {
        PasswordBox.Clear();
        ConfirmPasswordBox.Clear();
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // Keep confirm PasswordBox in sync when mode switch clears the property
        if (e.PropertyName == nameof(CipherViewModel.ConfirmPassword)
            && DataContext is CipherViewModel vm
            && vm.ConfirmPassword == string.Empty
            && ConfirmPasswordBox.Password.Length > 0)
        {
            ConfirmPasswordBox.Clear();
        }
    }
}
