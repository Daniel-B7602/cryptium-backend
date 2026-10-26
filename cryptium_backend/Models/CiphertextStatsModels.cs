namespace cryptium_backend.Models
{
    public class CiphertextStatsRequest
    {
        public string CiphertextBase64 { get; set; } = string.Empty;

        public bool HasIvPrefix { get; set; } = true;
    }

    public class CiphertextStatsResponse
    {
        public int TotalBytesReceived { get; set; }

        public int IvBytesLength { get; set; }

        public string IvHex { get; set; } = string.Empty;

        public int PayloadBytesLength { get; set; }

        public double Entropy { get; set; }

        public int UniqueBytesCount { get; set; }

        public double SpaceCoveragePercentage { get; set; }

        public Dictionary<int, int> Frequency { get; set; } = new();

        public int RepeatedBlocksCount { get; set; }

        public int Total16ByteBlocks { get; set; }
    }
}
