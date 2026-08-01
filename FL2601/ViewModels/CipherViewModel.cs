using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using FL2601.Services;

namespace FL2601.ViewModels;

public class CipherViewModel : INotifyPropertyChanged
{
    private bool _isEncryptMode = true;
    private string _password = string.Empty;
    private string _confirmPassword = string.Empty;
    private string _inputText = string.Empty;
    private string _resultText = string.Empty;
    private string _statusMessage = string.Empty;
    private SolidColorBrush _statusBrush = new(Color.FromRgb(0xD6, 0xD6, 0xD6));
    private bool _isBusy;

    public event Action? PasswordsClearRequested;

    public CipherViewModel()
    {
        EncryptCommand = new RelayCommand(async _ =>
        {
            try { await ExecuteAsync(); }
            catch (Exception ex) { SetStatus($"Unexpected error: {ex.Message}", true); }
        }, _ => CanExecute());
        CopyCommand = new RelayCommand(_ => CopyResult(), _ => !string.IsNullOrEmpty(ResultText));
        ClearCommand = new RelayCommand(_ => Clear());
        SetEncryptModeCommand = new RelayCommand(_ => IsEncryptMode = true);
        SetDecryptModeCommand = new RelayCommand(_ => IsEncryptMode = false);
    }

    public bool IsEncryptMode
    {
        get => _isEncryptMode;
        set
        {
            if (SetField(ref _isEncryptMode, value))
            {
                OnPropertyChanged(nameof(IsDecryptMode));
                OnPropertyChanged(nameof(ActionLabel));
                OnPropertyChanged(nameof(ConfirmPasswordVisible));
                ConfirmPassword = string.Empty;
                StatusMessage = string.Empty;
            }
        }
    }

    public bool IsDecryptMode => !_isEncryptMode;
    public string ActionLabel => _isEncryptMode ? "ENCRYPT" : "DECRYPT";
    public Visibility ConfirmPasswordVisible => _isEncryptMode ? Visibility.Visible : Visibility.Collapsed;

    public string Password
    {
        get => _password;
        set => SetField(ref _password, value);
    }

    public string ConfirmPassword
    {
        get => _confirmPassword;
        set => SetField(ref _confirmPassword, value);
    }

    public string InputText
    {
        get => _inputText;
        set => SetField(ref _inputText, value);
    }

    public string ResultText
    {
        get => _resultText;
        set => SetField(ref _resultText, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetField(ref _statusMessage, value);
    }

    public SolidColorBrush StatusBrush
    {
        get => _statusBrush;
        set => SetField(ref _statusBrush, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetField(ref _isBusy, value);
    }

    public ICommand EncryptCommand { get; }
    public ICommand CopyCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand SetEncryptModeCommand { get; }
    public ICommand SetDecryptModeCommand { get; }

    private bool CanExecute() => !IsBusy && !string.IsNullOrEmpty(Password) && !string.IsNullOrEmpty(InputText);

    private async Task ExecuteAsync()
    {
        if (IsEncryptMode)
            await DoEncryptAsync();
        else
            await DoDecryptAsync();
    }

    private async Task DoEncryptAsync()
    {
        if (Password != ConfirmPassword)
        {
            SetStatus("Passwords do not match.", true);
            return;
        }

        if (string.IsNullOrWhiteSpace(InputText))
        {
            SetStatus("Input text is empty.", true);
            return;
        }

        IsBusy = true;
        SetStatus("Encrypting...", false);

        try
        {
            string result = await Task.Run(() =>
            {
                string base64 = CipherEngine.Encrypt(InputText, Password);
                return MessageArmor.Wrap(base64, "FL2601-Windows");
            });

            ResultText = result;
            SetStatus("Encrypted successfully.", false);
        }
        catch (Exception ex)
        {
            SetStatus($"Encryption failed: {ex.Message}", true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task DoDecryptAsync()
    {
        if (string.IsNullOrWhiteSpace(InputText))
        {
            SetStatus("Input text is empty.", true);
            return;
        }

        IsBusy = true;
        SetStatus("Decrypting...", false);

        try
        {
            string result = await Task.Run(() =>
            {
                string base64 = MessageArmor.Unwrap(InputText);
                return CipherEngine.Decrypt(base64, Password);
            });

            ResultText = result;
            SetStatus("Decrypted successfully.", false);
        }
        catch (CryptographicException ex)
        {
            SetStatus(ex.Message, true);
        }
        catch (Exception ex)
        {
            SetStatus($"Decryption failed: {ex.Message}", true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void CopyResult()
    {
        try
        {
            Clipboard.SetText(ResultText);
            SetStatus("Copied to clipboard.", false);
        }
        catch (Exception)
        {
            SetStatus("Clipboard is in use by another application.", true);
        }
    }

    private void Clear()
    {
        Password = string.Empty;
        ConfirmPassword = string.Empty;
        InputText = string.Empty;
        ResultText = string.Empty;
        StatusMessage = string.Empty;
        PasswordsClearRequested?.Invoke();
    }

    private void SetStatus(string message, bool isError)
    {
        StatusMessage = message;
        StatusBrush = isError
            ? new SolidColorBrush(Color.FromRgb(0xFF, 0x44, 0x44))
            : new SolidColorBrush(Color.FromRgb(0x33, 0xFF, 0x33));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
