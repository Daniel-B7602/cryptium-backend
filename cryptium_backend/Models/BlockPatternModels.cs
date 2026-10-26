namespace cryptium_backend.Models
{
    public class BlockPatternRequest
    {
        public string Text { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty;
    }

    public class BlockItem
    {
        public int Index { get; set; }

        public string PlaintextAscii { get; set; } = string.Empty;

        public string PlaintextHex { get; set; } = string.Empty;

        public bool IsPlaintextDuplicate { get; set; }

        public int PlaintextDuplicateGroup { get; set; }

        public string EcbCipherHex { get; set; } = string.Empty;

        public bool IsEcbDuplicate { get; set; }

        public int EcbDuplicateGroup { get; set; }

        public string CbcCipherHex { get; set; } = string.Empty;

        public bool IsCbcDuplicate { get; set; }
    }

    public class BlockPatternResponse
    {
        public int TotalBlocks { get; set; }

        public int PlaintextDuplicatesCount { get; set; }

        public int EcbDuplicateBlockCount { get; set; }

        public int CbcDuplicateBlockCount { get; set; }

        public bool PatternPreservedInEcb { get; set; }

        public bool PatternPreservedInCbc { get; set; }

        public string CbcIvHex { get; set; } = string.Empty;

        public List<BlockItem> Blocks { get; set; } = new();

        public string Explanation { get; set; } = string.Empty;
    }
}
