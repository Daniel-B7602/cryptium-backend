namespace cryptium_backend.Models
{
    public class AvalancheBatchRequest
    {
        public string Text { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty;

        public string Target { get; set; } = "text"; // "text" | "key"

        public int SampleCount { get; set; } = 10;
    }

    public class AvalancheSampleItem
    {
        public int SampleIndex { get; set; }

        public string FlippedTarget { get; set; } = string.Empty;

        public string FlippedBitInfo { get; set; } = string.Empty;

        public int DifferentBits { get; set; }

        public int TotalBits { get; set; }

        public double AvalanchePercentage { get; set; }
    }

    public class AvalancheBatchSummary
    {
        public string Target { get; set; } = string.Empty;

        public int SampleCount { get; set; }

        public double AveragePercentage { get; set; }

        public double MinPercentage { get; set; }

        public double MaxPercentage { get; set; }

        public double StandardDeviation { get; set; }

        public int TotalBitsComparedPerSample { get; set; }
    }

    public class AvalancheBatchResponse
    {
        public AvalancheBatchSummary Summary { get; set; } = new();

        public List<AvalancheSampleItem> Samples { get; set; } = new();

        public string OriginalText { get; set; } = string.Empty;

        public string DerivedKeyHex { get; set; } = string.Empty;

        public string IvHex { get; set; } = string.Empty;
    }
}
