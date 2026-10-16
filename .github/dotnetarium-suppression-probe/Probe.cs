// Rescan: insert a line to exercise fingerprint stability across line movement.
// Intentionally insecure, isolated fixture for testing SARIF transport only.
using System.Security.Cryptography;

public static class SarifTransportProbe
{
    public static Aes Create()
    {
        var cipher = Aes.Create();
        cipher.Mode = CipherMode.ECB;
        return cipher;
    }
}
