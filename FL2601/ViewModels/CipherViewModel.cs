using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using FL2601.Services;

namespace FL2601.ViewModels;

public enum CipherMode
{
    Encrypt,
    Decrypt
}

/// <summary>
/// Whether the confirmation field currently agrees with the passphrase.
/// <see cref="NotShown"/> while decrypting, <see cref="Pending"/> until the user
/// has typed something, so the UI does not flash a mismatch on the first
/// keystroke.
/// </summary>
public enum ConfirmationState
{
    NotShown,
    Pending,
    Match,
    Mismatch
}

public enum StatusKind
{
    Idle,
    Working,
    Ok,
    Failed
}

public class CipherViewModel : INotifyPropertyChanged
{
    private static readonly Brush Green = Frozen(0x33, 0xFF, 0x33);
    private static readonly Brush Error = Frozen(0xFF, 0x44, 0x44);
    private static readonly Brush Caution = Frozen(0xE0, 0xA0, 0x2A);
    private static readonly Brush Text = Frozen(0xD6, 0xD6, 0xD6);
    private static readonly Brush Border = Frozen(0x38, 0x38, 0x38);

    private CipherMode _mode = CipherMode.Encrypt;
    private string _passphrase = string.Empty;
    private string _confirmPassphrase = string.Empty;
    private string _inputText = string.Empty;
    private string _result = string.Empty;
    private bool _showResult;
    private StatusKind _statusKind = StatusKind.Idle;
    private string _statusMessage = string.Empty;
    private bool _isProcessing;
    private bool _didJustCopy;
    private PayloadInfo? _payloadInfo;

    private readonly DispatcherTimer _copyResetTimer;

    public event Action? PassphrasesClearRequested;

    public CipherViewModel()
    {
        ProcessCommand = new RelayCommand(async _ =>
        {
            try { await ProcessAsync(); }
            catch (Exception ex) { Fail($"Unexpected error: {ex.Message}"); }
        }, _ => CanSubmit);
        CopyCommand = new RelayCommand(_ => CopyResult(), _ => !string.IsNullOrEmpty(Result));
        ClearCommand = new RelayCommand(_ => ClearAll());

        _copyResetTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _copyResetTimer.Tick += (_, _) =>
        {
            _copyResetTimer.Stop();
            DidJustCopy = false;
        };
    }

    // MARK: - Mode

    public CipherMode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value) return;
            _mode = value;

            // Hide output when switching modes to avoid confusion.
            ShowResult = false;
            PayloadInfo = null;
            SetStatus(StatusKind.Idle, string.Empty);
            // Decrypt has no confirmation field; drop the value rather than
            // leave it to reappear stale when the user switches back.
            ConfirmPassphrase = string.Empty;

            Notify(nameof(Mode), nameof(IsEncryptMode), nameof(IsDecryptMode),
                   nameof(RequiresConfirmation), nameof(InputLabel), nameof(ActionLabel),
                   nameof(InputPrompt));
            NotifyConfirmation();
            NotifyStrength();
            RequeryCommands();
        }
    }

    /// <summary>
    /// Two-way so the tab can drive the mode directly. A radio group writes
    /// <c>false</c> to the sibling it deselects; only the <c>true</c> edge means
    /// anything here.
    /// </summary>
    public bool IsEncryptMode
    {
        get => _mode == CipherMode.Encrypt;
        set { if (value) Mode = CipherMode.Encrypt; }
    }

    public bool IsDecryptMode
    {
        get => _mode == CipherMode.Decrypt;
        set { if (value) Mode = CipherMode.Decrypt; }
    }

    public string InputLabel => _mode == CipherMode.Encrypt ? "PLAINTEXT LETTER" : "CIPHERTEXT (BASE64)";
    public string ActionLabel => _mode == CipherMode.Encrypt ? "ENCRYPT TEXT" : "DECRYPT TEXT";

    public string InputPrompt => _mode == CipherMode.Encrypt
        ? "Type or paste text here..."
        : "Paste base64 ciphertext here...";

    private string SuccessMessage => _mode == CipherMode.Encrypt
        ? "Encryption successful."
        : "Decryption successful.";

    // MARK: - Passphrase

    public string Passphrase
    {
        get => _passphrase;
        set
        {
            if (!SetField(ref _passphrase, value)) return;
            Notify(nameof(PassphrasePromptVisibility));
            NotifyConfirmation();
            NotifyStrength();
            RequeryCommands();
        }
    }

    public string ConfirmPassphrase
    {
        get => _confirmPassphrase;
        set
        {
            if (!SetField(ref _confirmPassphrase, value)) return;
            Notify(nameof(ConfirmPromptVisibility));
            NotifyConfirmation();
            RequeryCommands();
        }
    }

    /// <summary>
    /// Only encryption confirms. When decrypting, a mistyped passphrase simply
    /// fails to decrypt, so a second field would add friction and catch nothing.
    /// </summary>
    public bool RequiresConfirmation => _mode == CipherMode.Encrypt;

    public Visibility ConfirmationVisibility => RequiresConfirmation ? Visibility.Visible : Visibility.Collapsed;

    public ConfirmationState Confirmation
    {
        get
        {
            if (!RequiresConfirmation) return ConfirmationState.NotShown;
            if (_confirmPassphrase.Length == 0) return ConfirmationState.Pending;
            return _passphrase == _confirmPassphrase ? ConfirmationState.Match : ConfirmationState.Mismatch;
        }
    }

    public string ConfirmationText => Confirmation switch
    {
        ConfirmationState.Match => "[ MATCH ]",
        ConfirmationState.Mismatch => "[ NO MATCH ]",
        _ => string.Empty
    };

    public Brush ConfirmationBrush => Confirmation == ConfirmationState.Mismatch ? Error : Green;

    public Visibility PassphrasePromptVisibility => Prompt(_passphrase);
    public Visibility ConfirmPromptVisibility => Prompt(_confirmPassphrase);
    public Visibility InputPromptVisibility => Prompt(_inputText);

    // MARK: - Strength meter

    /// <summary>
    /// Only shown while encrypting. When decrypting you are typing a passphrase
    /// that already exists, and rating it would be noise.
    /// </summary>
    private PassphraseStrength.Estimate? Strength =>
        RequiresConfirmation ? PassphraseStrength.Measure(_passphrase) : null;

    public Visibility StrengthVisibility => RequiresConfirmation ? Visibility.Visible : Visibility.Collapsed;

    public GridLength StrengthFilledWidth => new(Strength?.Fraction ?? 0, GridUnitType.Star);
    public GridLength StrengthRemainingWidth => new(1 - (Strength?.Fraction ?? 0), GridUnitType.Star);

    /// <summary>
    /// No track until there is something to measure, otherwise an empty meter
    /// reads as a stray rule under the field.
    /// </summary>
    public Brush StrengthTrackBrush => Strength is null ? Brushes.Transparent : Border;

    public Brush StrengthBrush => Strength?.Band switch
    {
        PassphraseStrength.Band.Weak => Error,
        PassphraseStrength.Band.Fair => Caution,
        PassphraseStrength.Band.Strong or PassphraseStrength.Band.VeryStrong => Green,
        _ => Border
    };

    public string StrengthReadout => Strength is { } e ? $"~{e.Bits} bits · {e.Label}" : string.Empty;

    // MARK: - Input

    public string InputText
    {
        get => _inputText;
        set
        {
            if (!SetField(ref _inputText, value)) return;
            Notify(nameof(InputPromptVisibility), nameof(InputCounterText));
            RequeryCommands();
        }
    }

    public string InputCounterText
    {
        get
        {
            if (_inputText.Length == 0) return string.Empty;
            int characters = new StringInfo(_inputText).LengthInTextElements;
            int bytes = Encoding.UTF8.GetByteCount(_inputText);
            return $"{characters:N0} chars · {bytes:N0} bytes";
        }
    }

    // MARK: - Result

    public string Result
    {
        get => _result;
        set
        {
            if (SetField(ref _result, value))
                RequeryCommands();
        }
    }

    public bool ShowResult
    {
        get => _showResult;
        set
        {
            if (!SetField(ref _showResult, value)) return;
            Notify(nameof(ResultVisibility), nameof(IdleVisibility));
        }
    }

    public Visibility ResultVisibility => _showResult ? Visibility.Visible : Visibility.Collapsed;
    public Visibility IdleVisibility => _showResult ? Visibility.Collapsed : Visibility.Visible;

    public bool DidJustCopy
    {
        get => _didJustCopy;
        set
        {
            if (SetField(ref _didJustCopy, value))
                Notify(nameof(CopyLabel));
        }
    }

    public string CopyLabel => _didJustCopy ? "COPIED!" : "COPY TO CLIPBOARD";

    /// <summary>
    /// A blinking cursor is decoration; skip it when the user has asked the
    /// system to keep animation still.
    /// </summary>
    public bool AnimateCursor => SystemParameters.ClientAreaAnimation;

    // MARK: - Payload map

    /// <summary>
    /// Structure of the payload most recently produced or read. Populated from
    /// the header alone, so it costs nothing and discloses nothing.
    /// </summary>
    public PayloadInfo? PayloadInfo
    {
        get => _payloadInfo;
        private set
        {
            if (!SetField(ref _payloadInfo, value)) return;
            Notify(nameof(PayloadVisibility), nameof(PayloadSummary),
                   nameof(PublicWidth), nameof(CiphertextWidth),
                   nameof(PublicSegmentText), nameof(CiphertextSegmentText));
        }
    }

    public Visibility PayloadVisibility => _payloadInfo is null ? Visibility.Collapsed : Visibility.Visible;

    private int OverheadBytes => _payloadInfo is null ? 0 : _payloadInfo.TotalBytes - _payloadInfo.CiphertextBytes;

    // Drawn to true scale; the minimum widths on the columns take over only when
    // a segment's real share would round to an unreadable sliver.
    public GridLength PublicWidth => new(OverheadBytes, GridUnitType.Star);
    public GridLength CiphertextWidth => new(_payloadInfo?.CiphertextBytes ?? 0, GridUnitType.Star);

    public string PublicSegmentText => $"PUBLIC {OverheadBytes} B";
    public string CiphertextSegmentText => $"CIPHERTEXT {_payloadInfo?.CiphertextBytes ?? 0:N0} B";

    public string PayloadSummary => _payloadInfo is not { } info
        ? string.Empty
        : $"{info.TotalBytes:N0} bytes · v{info.Version} · "
          + $"{info.Iterations:N0} rounds · "
          + $"{OverheadBytes} bytes public framing · "
          + $"{info.PlaintextBytes:N0} bytes encrypted";

    // MARK: - Status

    public bool IsProcessing
    {
        get => _isProcessing;
        private set
        {
            if (!SetField(ref _isProcessing, value)) return;
            Notify(nameof(ProcessingVisibility));
            RequeryCommands();
        }
    }

    public Visibility ProcessingVisibility => _isProcessing ? Visibility.Visible : Visibility.Collapsed;

    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetField(ref _statusMessage, value);
    }

    public Brush StatusBrush => _statusKind switch
    {
        StatusKind.Working => Text,
        StatusKind.Ok => Green,
        StatusKind.Failed => Error,
        _ => Brushes.Transparent
    };

    /// <summary>
    /// What the app is actually doing, named rather than described as
    /// "processing". The pause has a cause and the cause is interesting.
    /// </summary>
    public string WorkingDescription =>
        $"deriving key · {CipherEngine.DefaultIterations:N0} rounds · PBKDF2-HMAC-SHA256";

    /// <summary>
    /// Read from the format constant rather than hardcoded, so the copy cannot
    /// drift from what the app actually does.
    /// </summary>
    public string InstructionsText =>
        $"This tool uses PBKDF2 for key derivation ({CipherEngine.DefaultIterations:N0} iterations, "
        + "SHA-256) and AES-256-GCM for encryption.";

    // MARK: - Commands

    public RelayCommand ProcessCommand { get; }
    public RelayCommand CopyCommand { get; }
    public RelayCommand ClearCommand { get; }

    public bool CanSubmit
    {
        get
        {
            if (IsProcessing || _passphrase.Length == 0 || _inputText.Length == 0) return false;
            return !RequiresConfirmation || _passphrase == _confirmPassphrase;
        }
    }

    private async Task ProcessAsync()
    {
        if (IsProcessing) return;

        if (_passphrase.Length == 0)
        {
            Fail("Passphrase is required.");
            return;
        }

        if (RequiresConfirmation && _passphrase != _confirmPassphrase)
        {
            Fail("Passphrases do not match.");
            return;
        }

        if (string.IsNullOrWhiteSpace(_inputText))
        {
            Fail("Input is required.");
            return;
        }

        IsProcessing = true;
        SetStatus(StatusKind.Working, WorkingDescription);

        CipherMode mode = _mode;
        string passphrase = _passphrase;
        string inputText = _inputText;

        try
        {
            (string output, string inspected) = await Task.Run(() =>
            {
                if (mode == CipherMode.Encrypt)
                {
                    // The engine returns the payload; the envelope is added here
                    // because it is presentation, not format.
                    string payload = CipherEngine.Encrypt(inputText, passphrase);
                    return (MessageArmor.Wrap(payload, "FL2601-Windows"), payload);
                }

                // Report the structure of what was read, not of the plaintext.
                return (CipherEngine.Decrypt(inputText, passphrase), inputText);
            });

            Result = output;
            // Never let a failure to describe the payload sink a successful
            // operation: this is a readout, not part of the result.
            PayloadInfo = TryInspect(inspected);
            ShowResult = true;
            SetStatus(StatusKind.Ok, SuccessMessage);
        }
        catch (CryptographicException ex)
        {
            Fail(ex.Message);
        }
        catch (Exception ex)
        {
            Fail($"{(mode == CipherMode.Encrypt ? "Encryption" : "Decryption")} failed: {ex.Message}");
        }
        finally
        {
            IsProcessing = false;
        }
    }

    private static PayloadInfo? TryInspect(string payload)
    {
        try { return CipherEngine.Inspect(payload); }
        catch (Exception) { return null; }
    }

    private void CopyResult()
    {
        if (string.IsNullOrEmpty(Result)) return;

        try
        {
            Clipboard.SetText(Result);
            DidJustCopy = true;
            _copyResetTimer.Stop();
            _copyResetTimer.Start();
        }
        catch (Exception)
        {
            Fail("Clipboard is in use by another application.");
        }
    }

    private void ClearAll()
    {
        Passphrase = string.Empty;
        ConfirmPassphrase = string.Empty;
        InputText = string.Empty;
        Result = string.Empty;
        PayloadInfo = null;
        ShowResult = false;
        SetStatus(StatusKind.Idle, string.Empty);
        PassphrasesClearRequested?.Invoke();
    }

    private void Fail(string message)
    {
        SetStatus(StatusKind.Failed, message);
        Result = string.Empty;
        PayloadInfo = null;
        ShowResult = false;
    }

    private void SetStatus(StatusKind kind, string message)
    {
        _statusKind = kind;
        StatusMessage = message;
        Notify(nameof(StatusBrush));
    }

    // MARK: - Change notification

    public event PropertyChangedEventHandler? PropertyChanged;

    private void NotifyConfirmation() =>
        Notify(nameof(Confirmation), nameof(ConfirmationText), nameof(ConfirmationBrush),
               nameof(ConfirmationVisibility));

    private void NotifyStrength() =>
        Notify(nameof(StrengthVisibility), nameof(StrengthFilledWidth), nameof(StrengthRemainingWidth),
               nameof(StrengthTrackBrush), nameof(StrengthBrush), nameof(StrengthReadout));

    private void Notify(params string[] names)
    {
        foreach (string name in names)
            OnPropertyChanged(name);
    }

    /// <summary>
    /// Every property that gates <see cref="CanSubmit"/> or the copy button
    /// calls this, so enablement is never a frame behind the state it reflects.
    /// </summary>
    private void RequeryCommands()
    {
        ProcessCommand.RaiseCanExecuteChanged();
        CopyCommand.RaiseCanExecuteChanged();
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private static Visibility Prompt(string text) =>
        text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
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

    public event EventHandler? CanExecuteChanged;

    /// <summary>
    /// Raised by the view model rather than routed through
    /// <see cref="CommandManager"/>. What gates these commands is view-model
    /// state — a passphrase that now matches, a run that just finished — not
    /// keyboard or focus activity, and the CommandManager's deferred requery
    /// left buttons showing stale enablement.
    /// </summary>
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
