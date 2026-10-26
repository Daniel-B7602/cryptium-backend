namespace cryptium_backend.Models
{
    public class AvalancheResponse
    {
        public string OriginalText { get; set; } = string.Empty;

        public string ModifiedText { get; set; } = string.Empty;

        public string OriginalByteHex { get; set; } = string.Empty;

        public string ModifiedByteHex { get; set; } = string.Empty;

        public string OriginalByteBinary { get; set; } = string.Empty;

        public string ModifiedByteBinary { get; set; } = string.Empty;

        public string FlippedBitInfo { get; set; } = string.Empty;

        public int DifferentBits { get; set; }

        public int TotalBits { get; set; }

        public double AvalanchePercentage { get; set; }

        public string OriginalCiphertextBase64 { get; set; } = string.Empty;

        public string ModifiedCiphertextBase64 { get; set; } = string.Empty;

        public string IvHex { get; set; } = string.Empty;

        public int BlockCount { get; set; }

        public int CiphertextBytesCompared { get; set; }
    }
}
