namespace cryptium_backend.Models
{
    public class AudioCapacityResponse
    {
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public double DurationSeconds { get; set; }
        public int SampleRate { get; set; }
        public int Channels { get; set; }
        public int BitsPerSample { get; set; }
        public long TotalSamples { get; set; }
        public int MaxMessageBytes { get; set; }
        public int MaxMessageChars { get; set; }
        public string AudioFormat { get; set; } = string.Empty;
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class AudioAnalysisResponse : AudioCapacityResponse
    {
        public int BlockAlign { get; set; }
        public long ByteRate { get; set; }
        public double DynamicRangeDb { get; set; }

        // Diagnóstico de presencia de esteganografía
        public bool HasCryptiumPayload { get; set; }
        public byte? PayloadVersion { get; set; }
        public int? PayloadSizeBytes { get; set; }
        public double? PayloadCapacityPercentage { get; set; }
        public long? RemainingSamples { get; set; }
        public string StegoStatusDescription { get; set; } = string.Empty;
    }

    public class AudioExtractResponse
    {
        public string Message { get; set; } = string.Empty;
        public int MessageBytes { get; set; }
        public string FileName { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public int SampleRate { get; set; }
        public int Channels { get; set; }
        public int BitsPerSample { get; set; }
        public bool IntegrityVerified { get; set; } = true;
    }

    public class AudioComparisonResponse
    {
        public string OriginalFileName { get; set; } = string.Empty;
        public string StegoFileName { get; set; } = string.Empty;
        public long TotalSamples { get; set; }
        public int Channels { get; set; }
        public int SampleRate { get; set; }
        public int BitsPerSample { get; set; }
        public double DurationSeconds { get; set; }

        // Métricas DSP
        public long ModifiedSamplesCount { get; set; }
        public double ModifiedSamplesPercentage { get; set; }
        public int MaxAbsoluteDifference { get; set; }
        public double MeanAbsoluteError { get; set; }
        public double MeanSquaredError { get; set; }
        public double RootMeanSquaredError { get; set; }
        public double? SignalToNoiseRatioDb { get; set; }
        public double? PeakSignalToNoiseRatioDb { get; set; }
        public bool IsIdentical { get; set; }
        public string SnrQualityAssessment { get; set; } = string.Empty;

        // Vectores de forma de onda submuestreados para Canvas (valores normalizados -1.0 a 1.0)
        public float[] WaveformOriginal { get; set; } = Array.Empty<float>();
        public float[] WaveformStego { get; set; } = Array.Empty<float>();
        public float[] WaveformDifference { get; set; } = Array.Empty<float>();

        public bool IsCompatible { get; set; } = true;
        public string? ErrorMessage { get; set; }
    }
}
