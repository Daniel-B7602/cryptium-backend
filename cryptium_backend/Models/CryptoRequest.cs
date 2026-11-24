namespace cryptium_backend.Models
{
    public class CryptoRequest
    {
        public string Text { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty;

        public string Algorithm { get; set; } = "AES";
    }

    public class RsaKeyPairResponse
    {
        public string PublicKey { get; set; } = string.Empty;

        public string PrivateKey { get; set; } = string.Empty;

        public int KeySize { get; set; } = 2048;
    }

    public class CryptoResponse
    {
        public string? EncryptedText { get; set; }

        public string? DecryptedText { get; set; }

        public string Algorithm { get; set; } = "AES";

        public string? NonceOrIvHex { get; set; }

        public string? Details { get; set; }
    }
}
