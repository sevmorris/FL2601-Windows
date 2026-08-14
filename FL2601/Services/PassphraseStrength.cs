using System.Text;

namespace FL2601.Services;

/// <summary>
/// A deliberately simple estimate of how much entropy a passphrase carries.
///
/// <para><b>What this measures.</b> The size of the character pool in use,
/// multiplied by an effective length that discounts repetition. Nothing more.</para>
///
/// <para><b>What it does not measure.</b> Predictability. <c>Password123!</c>
/// scores well here and would fall to a dictionary attack in seconds; a long
/// lowercase phrase of common words scores well and is not much better. A real
/// estimator needs a word list and pattern matching — zxcvbn is the reference —
/// and vendoring one is more dependency than this app is willing to carry.</para>
///
/// <para>So the readout is framed as an upper bound on typed entropy, not a
/// promise. It is here because the app's own threat model names passphrase
/// entropy as the weak link, and saying nothing at all was worse than saying
/// this with a caveat attached.</para>
/// </summary>
public static class PassphraseStrength
{
    public enum Band
    {
        Weak,
        Fair,
        Strong,
        VeryStrong
    }

    /// <summary>
    /// Thresholds chosen against this app's actual work factor. A serious GPU
    /// rig manages on the order of a million PBKDF2-SHA256 guesses per second
    /// at 600,000 iterations, so roughly 45 bits buys about a year.
    /// </summary>
    public readonly record struct Estimate(int Bits, Band Band)
    {
        /// <summary>0..1, for a meter. Saturates at 96 bits.</summary>
        public double Fraction => Math.Min(1.0, Bits / 96.0);

        public string Label => Band switch
        {
            Band.Weak => "weak",
            Band.Fair => "fair",
            Band.Strong => "strong",
            _ => "very strong"
        };
    }

    public static Estimate? Measure(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) return null;

        int bits = (int)Math.Round(EntropyBits(passphrase), MidpointRounding.AwayFromZero);
        Band band = bits switch
        {
            < 40 => Band.Weak,
            < 60 => Band.Fair,
            < 80 => Band.Strong,
            _ => Band.VeryStrong
        };
        return new Estimate(bits, band);
    }

    public static double EntropyBits(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase)) return 0;

        var scalars = new List<Rune>();
        bool sawLower = false, sawUpper = false, sawDigit = false;
        bool sawSymbol = false, sawNonAscii = false;

        foreach (Rune r in passphrase.EnumerateRunes())
        {
            scalars.Add(r);
            if (r.Value is >= 'a' and <= 'z') sawLower = true;
            else if (r.Value is >= 'A' and <= 'Z') sawUpper = true;
            else if (r.Value is >= '0' and <= '9') sawDigit = true;
            else if (r.IsAscii) sawSymbol = true;
            else sawNonAscii = true;
        }

        int pool = 0;
        if (sawLower) pool += 26;
        if (sawUpper) pool += 26;
        if (sawDigit) pool += 10;
        if (sawSymbol) pool += 33;    // printable ASCII punctuation
        if (sawNonAscii) pool += 100; // rough, and deliberately conservative
        if (pool <= 1) return 0;

        // Repetition earns less than novelty. Characters beyond the first
        // occurrence of each count half.
        int unique = new HashSet<Rune>(scalars).Count;
        int repeated = scalars.Count - unique;
        double effectiveLength = unique + repeated * 0.5;

        return effectiveLength * Math.Log2(pool);
    }
}
