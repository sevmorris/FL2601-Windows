using System.Text;

namespace FL2601.Services;

public static class MessageArmor
{
    private const string BeginMarker = "-----BEGIN FL2601 MESSAGE-----";
    private const string EndMarker = "-----END FL2601 MESSAGE-----";
    private const int LineWidth = 64;

    public static string Wrap(string base64, string? comment = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine(BeginMarker);

        if (!string.IsNullOrEmpty(comment))
            sb.AppendLine($"Comment: {comment}");

        sb.AppendLine();

        // Split base64 into 64-char lines
        for (int i = 0; i < base64.Length; i += LineWidth)
        {
            int len = Math.Min(LineWidth, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }

        sb.AppendLine(EndMarker);
        return sb.ToString().TrimEnd();
    }

    public static string Unwrap(string input)
    {
        string trimmed = input.Trim();

        // If no armor markers, treat as bare base64 and pass through
        int beginIdx = trimmed.IndexOf(BeginMarker, StringComparison.Ordinal);
        if (beginIdx < 0)
            return StripWhitespace(trimmed);

        int endIdx = trimmed.IndexOf(EndMarker, StringComparison.Ordinal);
        if (endIdx < 0)
            return StripWhitespace(trimmed);

        // Extract content between markers
        int contentStart = beginIdx + BeginMarker.Length;
        string content = trimmed[contentStart..endIdx];

        // Split into lines, strip comment lines (contain ':') and blank lines
        var sb = new StringBuilder();
        foreach (string rawLine in content.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0) continue;
            if (line.Contains(':')) continue;
            sb.Append(line);
        }

        return sb.ToString();
    }

    private static string StripWhitespace(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (!char.IsWhiteSpace(c))
                sb.Append(c);
        }
        return sb.ToString();
    }
}
