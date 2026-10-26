using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using cryptium_backend.Models;

namespace cryptium_backend.Services
{
    public class AnalysisService
    {
        public double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0)
                return 0;

            int[] frequencies = new int[256];

            foreach (byte b in data)
                frequencies[b]++;

            double entropy = 0;

            foreach (int frequency in frequencies)
            {
                if (frequency == 0)
                    continue;

                double probability =
                    (double)frequency / data.Length;

                entropy -= probability *
                           Math.Log2(probability);
            }

            return Math.Round(entropy, 4);
        }

        public Dictionary<int, int> CalculateFrequency(byte[] data)
        {
            int[] frequencies = new int[256];

            foreach (byte b in data)
                frequencies[b]++;

            Dictionary<int, int> result = new();

            for (int i = 0; i < frequencies.Length; i++)
            {
                if (frequencies[i] > 0)
                    result[i] = frequencies[i];
            }

            return result;
        }

        public double CalculateAvalanche(
            byte[] original,
            byte[] modified)
        {
            if (original.Length != modified.Length || original.Length == 0)
                return 0;

            int differentBits = 0;
            int totalBits = original.Length * 8;

            for (int i = 0; i < original.Length; i++)
            {
                byte difference =
                    (byte)(original[i] ^ modified[i]);

                differentBits +=
                    BitOperations.PopCount(difference);
            }

            return Math.Round(
                (double)differentBits / totalBits * 100,
                4
            );
        }

        public AvalancheResponse AnalyzeAvalanche(string text, string key)
        {
            // 1. Derivación de clave idéntica a CryptoService (SHA-256)
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            // 2. Preparar Entrada 1 (original)
            byte[] plainBytes1 = Encoding.UTF8.GetBytes(text);
            if (plainBytes1.Length == 0)
            {
                throw new ArgumentException("El texto no puede estar vacío.");
            }

            // 3. Preparar Entrada 2 (invertir exactamente 1 bit en el Byte 0: bit menos significativo LSB)
            byte[] plainBytes2 = (byte[])plainBytes1.Clone();
            byte origByte = plainBytes1[0];
            plainBytes2[0] ^= 0x01; // Inversión del bit 0
            byte modByte = plainBytes2[0];

            // 4. Cifrado AES controlado en entorno aislado con IV compartido
            using Aes aes = Aes.Create();
            aes.Key = keyBytes;
            aes.GenerateIV(); // Genera un IV aleatorio exclusivo para este experimento
            byte[] isolatedIv = aes.IV;

            // Cifrar primera entrada (obteniendo bloques de texto cifrado puros, sin prefijar el IV)
            using ICryptoTransform encryptor1 = aes.CreateEncryptor(keyBytes, isolatedIv);
            byte[] cipherBytes1 = encryptor1.TransformFinalBlock(plainBytes1, 0, plainBytes1.Length);

            // Cifrar segunda entrada con exactamente el mismo IV para comparación rigurosa
            using ICryptoTransform encryptor2 = aes.CreateEncryptor(keyBytes, isolatedIv);
            byte[] cipherBytes2 = encryptor2.TransformFinalBlock(plainBytes2, 0, plainBytes2.Length);

            // 5. Comparación estricta de bits sobre los bloques cifrados (excluyendo el IV)
            int differentBits = 0;
            int totalBits = cipherBytes1.Length * 8;

            for (int i = 0; i < cipherBytes1.Length; i++)
            {
                byte diff = (byte)(cipherBytes1[i] ^ cipherBytes2[i]);
                differentBits += BitOperations.PopCount(diff);
            }

            // Reutilización directa de CalculateAvalanche para mantener consistencia métrica
            double percentage = CalculateAvalanche(cipherBytes1, cipherBytes2);

            return new AvalancheResponse
            {
                OriginalText = text,
                ModifiedText = Encoding.UTF8.GetString(plainBytes2),
                OriginalByteHex = $"0x{origByte:X2}",
                ModifiedByteHex = $"0x{modByte:X2}",
                OriginalByteBinary = Convert.ToString(origByte, 2).PadLeft(8, '0'),
                ModifiedByteBinary = Convert.ToString(modByte, 2).PadLeft(8, '0'),
                FlippedBitInfo = "Byte 0, Bit 0 (LSB - Bit menos significativo)",
                DifferentBits = differentBits,
                TotalBits = totalBits,
                AvalanchePercentage = percentage,
                OriginalCiphertextBase64 = Convert.ToBase64String(cipherBytes1),
                ModifiedCiphertextBase64 = Convert.ToBase64String(cipherBytes2),
                IvHex = Convert.ToHexString(isolatedIv).ToLowerInvariant(),
                BlockCount = cipherBytes1.Length / 16,
                CiphertextBytesCompared = cipherBytes1.Length
            };
        }

        public AvalancheBatchResponse AnalyzeAvalancheBatch(AvalancheBatchRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                throw new ArgumentException("El texto no puede estar vacío.");

            if (string.IsNullOrWhiteSpace(request.Key))
                throw new ArgumentException("La clave no puede estar vacía.");

            int sampleCount = Math.Clamp(request.SampleCount, 2, 50);
            string target = request.Target?.Trim().ToLowerInvariant() == "key" ? "key" : "text";

            byte[] baseKeyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(request.Key));
            byte[] basePlainBytes = Encoding.UTF8.GetBytes(request.Text);

            using Aes aes = Aes.Create();
            aes.Key = baseKeyBytes;
            aes.GenerateIV();
            byte[] batchIv = aes.IV;

            // Cifrar base de referencia
            using ICryptoTransform baseEnc = aes.CreateEncryptor(baseKeyBytes, batchIv);
            byte[] baseCipherBytes = baseEnc.TransformFinalBlock(basePlainBytes, 0, basePlainBytes.Length);

            int totalBits = baseCipherBytes.Length * 8;
            List<AvalancheSampleItem> samples = new();

            for (int i = 0; i < sampleCount; i++)
            {
                byte[] testPlain = (byte[])basePlainBytes.Clone();
                byte[] testKey = (byte[])baseKeyBytes.Clone();
                string flippedInfo;

                if (target == "text")
                {
                    int byteIndex = (i / 8) % testPlain.Length;
                    int bitIndex = i % 8;
                    testPlain[byteIndex] ^= (byte)(1 << bitIndex);
                    flippedInfo = $"Byte {byteIndex}, Bit {bitIndex}";
                }
                else
                {
                    // Alterar exactamente 1 bit en la clave AES derivada de 256 bits (32 bytes)
                    int byteIndex = (i / 8) % testKey.Length;
                    int bitIndex = i % 8;
                    testKey[byteIndex] ^= (byte)(1 << bitIndex);
                    flippedInfo = $"Byte clave {byteIndex}, Bit {bitIndex}";
                }

                using ICryptoTransform sampleEnc = aes.CreateEncryptor(testKey, batchIv);
                byte[] sampleCipherBytes = sampleEnc.TransformFinalBlock(testPlain, 0, testPlain.Length);

                int diffBits = 0;
                for (int b = 0; b < baseCipherBytes.Length; b++)
                {
                    byte diff = (byte)(baseCipherBytes[b] ^ sampleCipherBytes[b]);
                    diffBits += BitOperations.PopCount(diff);
                }

                double pct = totalBits > 0 ? Math.Round((double)diffBits / totalBits * 100, 4) : 0;

                samples.Add(new AvalancheSampleItem
                {
                    SampleIndex = i + 1,
                    FlippedTarget = target == "text" ? "Texto plano" : "Clave derivada (256-bit)",
                    FlippedBitInfo = flippedInfo,
                    DifferentBits = diffBits,
                    TotalBits = totalBits,
                    AvalanchePercentage = pct
                });
            }

            double avg = Math.Round(samples.Average(s => s.AvalanchePercentage), 4);
            double min = Math.Round(samples.Min(s => s.AvalanchePercentage), 4);
            double max = Math.Round(samples.Max(s => s.AvalanchePercentage), 4);
            double variance = samples.Average(s => Math.Pow(s.AvalanchePercentage - avg, 2));
            double stdDev = Math.Round(Math.Sqrt(variance), 4);

            return new AvalancheBatchResponse
            {
                Summary = new AvalancheBatchSummary
                {
                    Target = target == "text" ? "Texto plano" : "Clave criptográfica",
                    SampleCount = samples.Count,
                    AveragePercentage = avg,
                    MinPercentage = min,
                    MaxPercentage = max,
                    StandardDeviation = stdDev,
                    TotalBitsComparedPerSample = totalBits
                },
                Samples = samples,
                OriginalText = request.Text,
                DerivedKeyHex = Convert.ToHexString(baseKeyBytes).ToLowerInvariant(),
                IvHex = Convert.ToHexString(batchIv).ToLowerInvariant()
            };
        }

        public BlockPatternResponse AnalyzeBlockPatterns(string text, string key)
        {
            if (string.IsNullOrWhiteSpace(text))
                throw new ArgumentException("El texto no puede estar vacío.");

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("La clave no puede estar vacía.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            byte[] plainBytes = Encoding.UTF8.GetBytes(text);

            // Cifrado ECB aislado
            using Aes aesEcb = Aes.Create();
            aesEcb.Mode = CipherMode.ECB;
            aesEcb.Padding = PaddingMode.PKCS7;
            aesEcb.Key = keyBytes;
            using var ecbEncryptor = aesEcb.CreateEncryptor();
            byte[] ecbCipher = ecbEncryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            // Cifrado CBC aislado con IV controlado
            using Aes aesCbc = Aes.Create();
            aesCbc.Mode = CipherMode.CBC;
            aesCbc.Padding = PaddingMode.PKCS7;
            aesCbc.Key = keyBytes;
            aesCbc.GenerateIV();
            byte[] cbcIv = aesCbc.IV;
            using var cbcEncryptor = aesCbc.CreateEncryptor(keyBytes, cbcIv);
            byte[] cbcCipher = cbcEncryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            int blockSize = 16;
            int blockCount = ecbCipher.Length / blockSize;

            // Padding PKCS7 en el texto en claro para visualización exacta de bloques
            byte[] paddedPlain = new byte[ecbCipher.Length];
            Buffer.BlockCopy(plainBytes, 0, paddedPlain, 0, plainBytes.Length);
            byte padValue = (byte)(paddedPlain.Length - plainBytes.Length);
            for (int p = plainBytes.Length; p < paddedPlain.Length; p++)
            {
                paddedPlain[p] = padValue;
            }

            List<BlockItem> blocks = new();
            Dictionary<string, int> plainGroupMap = new();
            Dictionary<string, int> ecbGroupMap = new();
            int nextPlainGroup = 1;
            int nextEcbGroup = 1;

            for (int i = 0; i < blockCount; i++)
            {
                byte[] pBlock = new byte[blockSize];
                byte[] eBlock = new byte[blockSize];
                byte[] cBlock = new byte[blockSize];

                Buffer.BlockCopy(paddedPlain, i * blockSize, pBlock, 0, blockSize);
                Buffer.BlockCopy(ecbCipher, i * blockSize, eBlock, 0, blockSize);
                Buffer.BlockCopy(cbcCipher, i * blockSize, cBlock, 0, blockSize);

                string pHex = Convert.ToHexString(pBlock).ToLowerInvariant();
                string eHex = Convert.ToHexString(eBlock).ToLowerInvariant();
                string cHex = Convert.ToHexString(cBlock).ToLowerInvariant();

                StringBuilder asciiSb = new();
                foreach (byte b in pBlock)
                {
                    asciiSb.Append(b >= 32 && b < 127 ? (char)b : '·');
                }

                if (!plainGroupMap.ContainsKey(pHex))
                {
                    plainGroupMap[pHex] = nextPlainGroup++;
                }
                if (!ecbGroupMap.ContainsKey(eHex))
                {
                    ecbGroupMap[eHex] = nextEcbGroup++;
                }

                blocks.Add(new BlockItem
                {
                    Index = i,
                    PlaintextAscii = asciiSb.ToString(),
                    PlaintextHex = pHex,
                    PlaintextDuplicateGroup = plainGroupMap[pHex],
                    EcbCipherHex = eHex,
                    EcbDuplicateGroup = ecbGroupMap[eHex],
                    CbcCipherHex = cHex,
                    IsCbcDuplicate = false
                });
            }

            var plainGroupCounts = blocks.GroupBy(b => b.PlaintextDuplicateGroup).ToDictionary(g => g.Key, g => g.Count());
            var ecbGroupCounts = blocks.GroupBy(b => b.EcbDuplicateGroup).ToDictionary(g => g.Key, g => g.Count());
            var cbcHexCounts = blocks.GroupBy(b => b.CbcCipherHex).ToDictionary(g => g.Key, g => g.Count());

            int plainDupes = 0;
            int ecbDupes = 0;
            int cbcDupes = 0;

            foreach (var b in blocks)
            {
                b.IsPlaintextDuplicate = plainGroupCounts[b.PlaintextDuplicateGroup] > 1;
                if (b.IsPlaintextDuplicate) plainDupes++;

                b.IsEcbDuplicate = ecbGroupCounts[b.EcbDuplicateGroup] > 1;
                if (b.IsEcbDuplicate) ecbDupes++;

                b.IsCbcDuplicate = cbcHexCounts[b.CbcCipherHex] > 1;
                if (b.IsCbcDuplicate) cbcDupes++;
            }

            return new BlockPatternResponse
            {
                TotalBlocks = blockCount,
                PlaintextDuplicatesCount = plainDupes,
                EcbDuplicateBlockCount = ecbDupes,
                CbcDuplicateBlockCount = cbcDupes,
                PatternPreservedInEcb = ecbDupes > 0,
                PatternPreservedInCbc = cbcDupes > 0,
                CbcIvHex = Convert.ToHexString(cbcIv).ToLowerInvariant(),
                Blocks = blocks,
                Explanation = "En modo ECB (Electronic Codebook), cada bloque de 16 bytes se cifra de forma estrictamente determinista e independiente. Si dos bloques en claro son idénticos (P_i = P_j), sus salidas cifradas serán forzosamente idénticas (C_i = C_j), filtrando la estructura y repetición del mensaje original. En modo CBC (Cipher Block Chaining), cada bloque en claro se combina mediante XOR con el bloque cifrado anterior antes de pasar por AES, rompiendo por completo la repetición de patrones."
            };
        }

        public CiphertextStatsResponse AnalyzeCiphertextStatistics(string ciphertextBase64, bool hasIvPrefix)
        {
            if (string.IsNullOrWhiteSpace(ciphertextBase64))
                throw new ArgumentException("El texto cifrado en Base64 no puede estar vacío.");

            byte[] dataBytes = Convert.FromBase64String(ciphertextBase64.Trim());
            if (dataBytes.Length == 0)
                throw new ArgumentException("El texto cifrado no contiene bytes válidos.");

            byte[] payloadBytes;
            byte[] ivBytes = Array.Empty<byte>();

            if (hasIvPrefix && dataBytes.Length > 16)
            {
                ivBytes = new byte[16];
                payloadBytes = new byte[dataBytes.Length - 16];
                Buffer.BlockCopy(dataBytes, 0, ivBytes, 0, 16);
                Buffer.BlockCopy(dataBytes, 16, payloadBytes, 0, payloadBytes.Length);
            }
            else
            {
                payloadBytes = dataBytes;
            }

            double entropy = CalculateEntropy(payloadBytes);
            Dictionary<int, int> freq = CalculateFrequency(payloadBytes);

            int repeatedBlocks = 0;
            int total16ByteBlocks = payloadBytes.Length / 16;
            if (total16ByteBlocks > 1)
            {
                HashSet<string> seen = new();
                for (int i = 0; i < total16ByteBlocks; i++)
                {
                    byte[] blk = new byte[16];
                    Buffer.BlockCopy(payloadBytes, i * 16, blk, 0, 16);
                    string hex = Convert.ToHexString(blk);
                    if (!seen.Add(hex))
                    {
                        repeatedBlocks++;
                    }
                }
            }

            return new CiphertextStatsResponse
            {
                TotalBytesReceived = dataBytes.Length,
                IvBytesLength = ivBytes.Length,
                IvHex = ivBytes.Length > 0 ? Convert.ToHexString(ivBytes).ToLowerInvariant() : string.Empty,
                PayloadBytesLength = payloadBytes.Length,
                Entropy = entropy,
                UniqueBytesCount = freq.Count,
                SpaceCoveragePercentage = Math.Round((double)freq.Count / 256.0 * 100.0, 2),
                Frequency = freq,
                RepeatedBlocksCount = repeatedBlocks,
                Total16ByteBlocks = total16ByteBlocks
            };
        }
    }
}