using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Expedition.Activation;

/// <summary>
/// Generates a stable machine fingerprint for binding activation keys to specific machines.
/// SHA256(machineName + "|" + machineGuid + "|" + userName)
/// </summary>
public static class MachineFingerprint
{
    private static string? _cached;

    /// <summary>
    /// Gets the machine fingerprint as a lowercase hex string (64 chars).
    /// Result is cached after first call.
    /// </summary>
    public static string Get()
    {
        if (_cached != null) return _cached;

        var machineName = Environment.MachineName;
        var userName = Environment.UserName;
        var machineGuid = GetMachineGuid();

        var input = $"{machineName}|{machineGuid}|{userName}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));

        _cached = Convert.ToHexString(hash).ToLowerInvariant();
        return _cached;
    }

    private static string GetMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            var value = key?.GetValue("MachineGuid");
            if (value is string guid && !string.IsNullOrEmpty(guid))
                return guid;
        }
        catch
        {
            // Registry access may fail in some environments
        }

        // Fallback: use processor count and OS version as additional entropy
        return $"{Environment.ProcessorCount}-{Environment.OSVersion.Version}";
    }
}
