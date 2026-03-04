namespace Expedition.Activation;

/// <summary>
/// Parsed session token data from a verified EST- token.
/// </summary>
public sealed class SessionToken
{
    public Guid KeyId { get; init; }
    public byte[] MachineIdHash { get; init; } = Array.Empty<byte>();
    public DateTime IssuedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public ushort PluginVersion { get; init; }
    public byte Flags { get; init; }

    /// <summary>True if the token has expired.</summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;

    /// <summary>True if the token was issued more than 4 hours ago and should be refreshed.</summary>
    public bool NeedsRefresh => (DateTime.UtcNow - IssuedAt).TotalHours > 4;

    /// <summary>
    /// True if the server was last contacted within the 24-hour grace period.
    /// Allows offline operation for short periods.
    /// </summary>
    public bool IsInGracePeriod(DateTime lastServerContact)
        => (DateTime.UtcNow - lastServerContact).TotalHours < 24;
}
