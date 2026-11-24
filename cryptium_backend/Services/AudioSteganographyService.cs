using System.Security.Cryptography;
using System.Text;
using cryptium_backend.Models;

namespace cryptium_backend.Services
{
    public class AudioSteganographyService
    {
        private static readonly byte[] MagicMarker = Encoding.ASCII.GetBytes("CSTM"); // Cryptium Stego Mark
        private const byte CurrentFormatVersion = 0x01; // Versión 1 del formato interno
        private const int Pbkdf2Iterations = 600000;   // 600.000 iteraciones según recomendación OWASP
        private const int SaltSizeBytes = 16;
        private const int NonceSizeBytes = 12;
        private const int TagSizeBytes = 16;
        private const int LengthPrefixSizeBytes = 4;
        private const int VersionSizeBytes = 1;

        // Encabezado total: Magic (4B) + Version (1B) + Salt (16B) + Nonce (12B) + Tag (16B) + Length (4B) = 53 bytes
        private const int HeaderSizeBytes = 4 + VersionSizeBytes + SaltSizeBytes + NonceSizeBytes + TagSizeBytes + LengthPrefixSizeBytes;

        public AudioCapacityResponse GetCapacity(byte[] fileBytes, string fileName)
        {
            var wav = WavPcmFile.Parse(fileBytes);
            long totalSamples = wav.TotalSamples;
            long maxPayloadBytes = (totalSamples / 8) - HeaderSizeBytes;
            if (maxPayloadBytes < 0) maxPayloadBytes = 0;

            return new AudioCapacityResponse
            {
                FileName = fileName,
                FileSize = fileBytes.Length,
                DurationSeconds = Math.Round(wav.DurationSeconds, 2),
                SampleRate = (int)wav.SampleRate,
                Channels = wav.Channels,
                BitsPerSample = wav.BitsPerSample,
                TotalSamples = totalSamples,
                MaxMessageBytes = (int)Math.Min(maxPayloadBytes, int.MaxValue),
                MaxMessageChars = (int)Math.Min(maxPayloadBytes, int.MaxValue),
                AudioFormat = $"PCM {wav.BitsPerSample}-bit ({(wav.Channels == 1 ? "Mono" : "Estéreo")})",
                IsValid = true
            };
        }

        public AudioAnalysisResponse AnalyzeAudio(byte[] fileBytes, string fileName)
        {
            var wav = WavPcmFile.Parse(fileBytes);
            long totalSamples = wav.TotalSamples;
            long maxPayloadBytes = (totalSamples / 8) - HeaderSizeBytes;
            if (maxPayloadBytes < 0) maxPayloadBytes = 0;

            var analysis = new AudioAnalysisResponse
            {
                FileName = fileName,
                FileSize = fileBytes.Length,
                DurationSeconds = Math.Round(wav.DurationSeconds, 2),
                SampleRate = (int)wav.SampleRate,
                Channels = wav.Channels,
                BitsPerSample = wav.BitsPerSample,
                TotalSamples = totalSamples,
                MaxMessageBytes = (int)Math.Min(maxPayloadBytes, int.MaxValue),
                MaxMessageChars = (int)Math.Min(maxPayloadBytes, int.MaxValue),
                AudioFormat = $"PCM {wav.BitsPerSample}-bit ({(wav.Channels == 1 ? "Mono" : "Estéreo")})",
                IsValid = true,
                BlockAlign = wav.BlockAlign,
                ByteRate = wav.ByteRate,
                DynamicRangeDb = Math.Round(6.02 * wav.BitsPerSample, 1),
                HasCryptiumPayload = false,
                StegoStatusDescription = "Audio limpio o sin marca Cryptium detectada (100% de capacidad disponible)."
            };

            // Escaneo forense pasivo de las muestras LSB iniciales buscando el encabezado CSTM
            if (totalSamples >= (long)HeaderSizeBytes * 8)
            {
                int bytesPerSample = wav.BitsPerSample / 8;
                int dataStart = wav.DataChunkOffset;
                int sampleIdx = 0;

                byte ReadByte()
                {
                    byte b = 0;
                    for (int bit = 7; bit >= 0; bit--)
                    {
                        int targetPos = dataStart + (sampleIdx * bytesPerSample);
                        int lsb = wav.RawBytes[targetPos] & 1;
                        b = (byte)((b << 1) | lsb);
                        sampleIdx++;
                    }
                    return b;
                }

                byte[] magicBytes = new byte[4];
                for (int i = 0; i < 4; i++) magicBytes[i] = ReadByte();
                string marker = Encoding.ASCII.GetString(magicBytes);

                if (marker == "CSTM")
                {
                    byte version = ReadByte();
                    // Saltar Salt (16B), Nonce (12B), Tag (16B)
                    for (int i = 0; i < SaltSizeBytes + NonceSizeBytes + TagSizeBytes; i++) ReadByte();

                    byte[] lenBytes = new byte[4];
                    for (int i = 0; i < 4; i++) lenBytes[i] = ReadByte();
                    int ciphertextLen = BitConverter.ToInt32(lenBytes, 0);

                    if (ciphertextLen > 0 && ciphertextLen <= (totalSamples / 8) - HeaderSizeBytes)
                    {
                        int totalPayload = HeaderSizeBytes + ciphertextLen;
                        analysis.HasCryptiumPayload = true;
                        analysis.PayloadVersion = version;
                        analysis.PayloadSizeBytes = totalPayload;
                        analysis.PayloadCapacityPercentage = Math.Round(((double)totalPayload * 8.0 / totalSamples) * 100.0, 2);
                        analysis.RemainingSamples = totalSamples - ((long)totalPayload * 8);
                        analysis.StegoStatusDescription =
                            $"Contiene carga esteganográfica Cryptium v{version} " +
                            $"({totalPayload:N0} bytes totales: 53 bytes de encabezado + {ciphertextLen:N0} bytes de mensaje cifrado).";
                    }
                    else
                    {
                        analysis.StegoStatusDescription = "Marca 'CSTM' presente pero los metadatos de longitud son inconsistentes o están alterados.";
                    }
                }
            }

            return analysis;
        }

        public byte[] HideMessage(byte[] audioBytes, string message, string passphrase)
        {
            if (string.IsNullOrEmpty(message))
            {
                throw new ArgumentException("El mensaje secreto no puede estar vacío.", nameof(message));
            }

            if (string.IsNullOrWhiteSpace(passphrase))
            {
                throw new ArgumentException("La contraseña criptográfica no puede estar vacía.", nameof(passphrase));
            }

            var wav = WavPcmFile.Parse(audioBytes);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // 1. Generar sal criptográfica aleatoria de 16 bytes y derivar clave de 256 bits mediante PBKDF2
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
            byte[] key256 = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(passphrase),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                32
            );

            // 2. Cifrar con AES-256-GCM (Nonce aleatorio de 12 bytes y Tag de 16 bytes)
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            byte[] tag = new byte[TagSizeBytes];
            byte[] ciphertext = new byte[messageBytes.Length];

            using (var aesGcm = new AesGcm(key256, TagSizeBytes))
            {
                aesGcm.Encrypt(nonce, messageBytes, ciphertext, tag);
            }

            // 3. Ensamblar encabezado binario:
            // [Magic: 4B ("CSTM")] [Version: 1B (0x01)] [Salt: 16B] [Nonce: 12B] [Tag: 16B] [Length: 4B] [Ciphertext: NB]
            int totalPayloadLength = HeaderSizeBytes + ciphertext.Length;
            long requiredSamples = (long)totalPayloadLength * 8;

            if (requiredSamples > wav.TotalSamples)
            {
                long maxAvailable = (wav.TotalSamples / 8) - HeaderSizeBytes;
                throw new InvalidOperationException(
                    $"El mensaje supera la capacidad máxima del archivo de audio. " +
                    $"Capacidad útil disponible: {Math.Max(0, maxAvailable)} bytes, requerido: {messageBytes.Length} bytes.");
            }

            byte[] payload = new byte[totalPayloadLength];
            int offset = 0;

            Buffer.BlockCopy(MagicMarker, 0, payload, offset, MagicMarker.Length);
            offset += MagicMarker.Length;

            payload[offset] = CurrentFormatVersion;
            offset += VersionSizeBytes;

            Buffer.BlockCopy(salt, 0, payload, offset, salt.Length);
            offset += salt.Length;

            Buffer.BlockCopy(nonce, 0, payload, offset, nonce.Length);
            offset += nonce.Length;

            Buffer.BlockCopy(tag, 0, payload, offset, tag.Length);
            offset += tag.Length;

            byte[] lengthBytes = BitConverter.GetBytes(ciphertext.Length);
            Buffer.BlockCopy(lengthBytes, 0, payload, offset, lengthBytes.Length);
            offset += lengthBytes.Length;

            Buffer.BlockCopy(ciphertext, 0, payload, offset, ciphertext.Length);

            // 4. Inyectar payload en muestras de audio usando LSB (1 bit por muestra)
            byte[] stegoWavBytes = wav.CloneRawBytes();
            int bytesPerSample = wav.BitsPerSample / 8;
            int dataStart = wav.DataChunkOffset;

            int sampleIndex = 0;
            for (int pIdx = 0; pIdx < payload.Length; pIdx++)
            {
                byte currentByte = payload[pIdx];
                for (int bit = 7; bit >= 0; bit--)
                {
                    int bitValue = (currentByte >> bit) & 1;
                    int targetBytePos = dataStart + (sampleIndex * bytesPerSample);

                    // Modificar bit menos significativo (LSB)
                    stegoWavBytes[targetBytePos] = (byte)((stegoWavBytes[targetBytePos] & 0xFE) | bitValue);
                    sampleIndex++;
                }
            }

            return stegoWavBytes;
        }

        public AudioExtractResponse ExtractMessage(byte[] audioBytes, string passphrase, string fileName)
        {
            if (string.IsNullOrWhiteSpace(passphrase))
            {
                throw new ArgumentException("La contraseña criptográfica no puede estar vacía.", nameof(passphrase));
            }

            var wav = WavPcmFile.Parse(audioBytes);
            int bytesPerSample = wav.BitsPerSample / 8;
            int dataStart = wav.DataChunkOffset;
            long totalSamples = wav.TotalSamples;

            if (totalSamples < (long)HeaderSizeBytes * 8)
            {
                throw new InvalidOperationException("El audio no contiene suficientes muestras para albergar un mensaje de Cryptium.");
            }

            // Función local para extraer bytes consecutivamente de los bits LSB
            int currentSample = 0;
            byte[] ReadBytesFromAudio(int count)
            {
                byte[] extracted = new byte[count];
                for (int i = 0; i < count; i++)
                {
                    byte b = 0;
                    for (int bit = 7; bit >= 0; bit--)
                    {
                        int targetPos = dataStart + (currentSample * bytesPerSample);
                        int lsb = wav.RawBytes[targetPos] & 1;
                        b = (byte)((b << 1) | lsb);
                        currentSample++;
                    }
                    extracted[i] = b;
                }
                return extracted;
            }

            // 1. Leer y validar Identificador Mágico (4 bytes "CSTM")
            byte[] extractedMagic = ReadBytesFromAudio(4);
            string marker = Encoding.ASCII.GetString(extractedMagic);
            if (marker != "CSTM")
            {
                throw new InvalidOperationException(
                    "El archivo no contiene un mensaje esteganográfico de Cryptium.");
            }

            // 2. Leer y validar Versión (1 byte)
            byte[] extractedVersion = ReadBytesFromAudio(1);
            if (extractedVersion[0] != CurrentFormatVersion)
            {
                throw new InvalidOperationException(
                    $"Versión de formato ({extractedVersion[0]}) no compatible. Se esperaba versión {CurrentFormatVersion}.");
            }

            // 3. Leer Salt, Nonce, Tag y Longitud del cifrado
            byte[] salt = ReadBytesFromAudio(SaltSizeBytes);
            byte[] nonce = ReadBytesFromAudio(NonceSizeBytes);
            byte[] tag = ReadBytesFromAudio(TagSizeBytes);
            byte[] lengthBytes = ReadBytesFromAudio(LengthPrefixSizeBytes);
            int ciphertextLength = BitConverter.ToInt32(lengthBytes, 0);

            if (ciphertextLength <= 0 || ciphertextLength > (totalSamples / 8) - HeaderSizeBytes)
            {
                throw new InvalidOperationException(
                    "Longitud de contenido inválida: los metadatos están corruptos o el audio fue alterado.");
            }

            // 4. Leer Texto Cifrado
            byte[] ciphertext = ReadBytesFromAudio(ciphertextLength);

            // 5. Derivar clave mediante PBKDF2 con la sal extraída (600.000 iteraciones)
            byte[] key256 = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(passphrase),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                32
            );

            // 6. Descifrar y validar autenticidad con AES-256-GCM
            byte[] plaintext = new byte[ciphertext.Length];
            try
            {
                using var aesGcm = new AesGcm(key256, TagSizeBytes);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }
            catch (CryptographicException)
            {
                throw new UnauthorizedAccessException(
                    "Contraseña incorrecta o el archivo de audio ha sido modificado (falló la verificación de autenticidad e integridad AES-GCM).");
            }

            string decryptedMessage = Encoding.UTF8.GetString(plaintext);

            return new AudioExtractResponse
            {
                Message = decryptedMessage,
                MessageBytes = plaintext.Length,
                FileName = fileName,
                Algorithm = $"AES-256-GCM + PBKDF2 ({Pbkdf2Iterations:N0} iteraciones)",
                SampleRate = (int)wav.SampleRate,
                Channels = wav.Channels,
                BitsPerSample = wav.BitsPerSample,
                IntegrityVerified = true
            };
        }

        public AudioComparisonResponse CompareAudio(
            byte[] originalBytes,
            string originalFileName,
            byte[] stegoBytes,
            string stegoFileName)
        {
            var wavOrig = WavPcmFile.Parse(originalBytes);
            var wavStego = WavPcmFile.Parse(stegoBytes);

            // 1. Validaciones estrictas de compatibilidad matemática
            if (wavOrig.AudioFormat != wavStego.AudioFormat)
            {
                throw new InvalidOperationException(
                    $"Incompatibilidad de formato: Original es formato ({wavOrig.AudioFormat}) y Stego es formato ({wavStego.AudioFormat}).");
            }

            if (wavOrig.SampleRate != wavStego.SampleRate)
            {
                throw new InvalidOperationException(
                    $"Incompatibilidad de frecuencia: Original a {wavOrig.SampleRate:N0} Hz vs Stego a {wavStego.SampleRate:N0} Hz. Deben ser idénticos.");
            }

            if (wavOrig.Channels != wavStego.Channels)
            {
                throw new InvalidOperationException(
                    $"Incompatibilidad de canales: Original tiene {wavOrig.Channels} canal(es) y Stego tiene {wavStego.Channels} canal(es).");
            }

            if (wavOrig.BitsPerSample != wavStego.BitsPerSample)
            {
                throw new InvalidOperationException(
                    $"Incompatibilidad de profundidad: Original es de {wavOrig.BitsPerSample} bits y Stego es de {wavStego.BitsPerSample} bits.");
            }

            if (wavOrig.TotalSamples != wavStego.TotalSamples)
            {
                throw new InvalidOperationException(
                    $"Incompatibilidad de muestras: Original contiene {wavOrig.TotalSamples:N0} muestras y Stego contiene {wavStego.TotalSamples:N0} muestras.");
            }

            long totalSamples = wavOrig.TotalSamples;
            int bitsPerSample = wavOrig.BitsPerSample;
            int bytesPerSample = bitsPerSample / 8;
            int dataStartOrig = wavOrig.DataChunkOffset;
            int dataStartStego = wavStego.DataChunkOffset;

            long modifiedCount = 0;
            int maxDiff = 0;
            double sumAbsDiff = 0.0;
            double sumSquaredDiff = 0.0;   // Energía del ruido (error esteganográfico)
            double sumSquaredSignal = 0.0; // Energía de la señal original

            // Vector submuestreado para visualización en Canvas (600 puntos)
            const int WaveformPoints = 600;
            float[] waveOriginal = new float[WaveformPoints];
            float[] waveStego = new float[WaveformPoints];
            float[] waveDiff = new float[WaveformPoints];

            double maxScale = bitsPerSample == 16 ? 32768.0 : 128.0;
            long samplesPerBucket = Math.Max(1, totalSamples / WaveformPoints);

            for (long i = 0; i < totalSamples; i++)
            {
                int sOrig;
                int sStego;

                if (bitsPerSample == 16)
                {
                    sOrig = BitConverter.ToInt16(wavOrig.RawBytes, dataStartOrig + (int)(i * bytesPerSample));
                    sStego = BitConverter.ToInt16(wavStego.RawBytes, dataStartStego + (int)(i * bytesPerSample));
                }
                else
                {
                    // 8-bit unsigned PCM
                    sOrig = wavOrig.RawBytes[dataStartOrig + (int)i];
                    sStego = wavStego.RawBytes[dataStartStego + (int)i];
                }

                int diff = Math.Abs(sOrig - sStego);
                if (diff > 0)
                {
                    modifiedCount++;
                    if (diff > maxDiff) maxDiff = diff;
                }

                sumAbsDiff += diff;
                sumSquaredDiff += (double)diff * diff;
                sumSquaredSignal += (double)sOrig * sOrig;

                // Muestreo para el gráfico Canvas
                int bucketIdx = (int)(i / samplesPerBucket);
                if (bucketIdx < WaveformPoints)
                {
                    float normOrig = (float)(sOrig / maxScale);
                    float normStego = (float)(sStego / maxScale);

                    if (Math.Abs(normOrig) > Math.Abs(waveOriginal[bucketIdx]))
                        waveOriginal[bucketIdx] = normOrig;

                    if (Math.Abs(normStego) > Math.Abs(waveStego[bucketIdx]))
                        waveStego[bucketIdx] = normStego;

                    if (diff > 0 && waveDiff[bucketIdx] == 0)
                        waveDiff[bucketIdx] = 1.0f; // Marca de presencia de inyección LSB en este sector
                }
            }

            double mae = totalSamples > 0 ? (sumAbsDiff / totalSamples) : 0;
            double mse = totalSamples > 0 ? (sumSquaredDiff / totalSamples) : 0;
            double rmse = Math.Sqrt(mse);

            bool isIdentical = modifiedCount == 0;
            double? snrDb = null;
            double? psnrDb = null;
            string assessment;

            if (isIdentical)
            {
                assessment = "Archivos 100% idénticos. No se detectó ninguna alteración en las muestras de audio.";
            }
            else
            {
                if (sumSquaredDiff > 0 && sumSquaredSignal > 0)
                {
                    double snr = 10.0 * Math.Log10(sumSquaredSignal / sumSquaredDiff);
                    snrDb = Math.Round(snr, 2);
                }

                double peakValue = bitsPerSample == 16 ? 32767.0 : 255.0;
                if (mse > 0)
                {
                    double psnr = 10.0 * Math.Log10((peakValue * peakValue) / mse);
                    psnrDb = Math.Round(psnr, 2);
                }

                if (snrDb.HasValue)
                {
                    if (snrDb.Value >= 75.0)
                        assessment = "Excelente (SNR > 75 dB): Distorsión acústica imperceptible al oído humano; el ruido esteganográfico se encuentra al nivel del piso de ruido cuántico.";
                    else if (snrDb.Value >= 50.0)
                        assessment = "Muy buena (SNR > 50 dB): Alteración mínima de muy baja perceptibilidad sonora.";
                    else
                        assessment = "Moderada: Existe energía apreciable introducida en el canal.";
                }
                else
                {
                    assessment = "Distorsión de baja perceptibilidad LSB calculada.";
                }
            }

            return new AudioComparisonResponse
            {
                OriginalFileName = originalFileName,
                StegoFileName = stegoFileName,
                TotalSamples = totalSamples,
                Channels = wavOrig.Channels,
                SampleRate = (int)wavOrig.SampleRate,
                BitsPerSample = wavOrig.BitsPerSample,
                DurationSeconds = Math.Round(wavOrig.DurationSeconds, 2),
                ModifiedSamplesCount = modifiedCount,
                ModifiedSamplesPercentage = totalSamples > 0 ? Math.Round(((double)modifiedCount / totalSamples) * 100.0, 4) : 0,
                MaxAbsoluteDifference = maxDiff,
                MeanAbsoluteError = Math.Round(mae, 6),
                MeanSquaredError = Math.Round(mse, 6),
                RootMeanSquaredError = Math.Round(rmse, 6),
                SignalToNoiseRatioDb = snrDb,
                PeakSignalToNoiseRatioDb = psnrDb,
                IsIdentical = isIdentical,
                SnrQualityAssessment = assessment,
                WaveformOriginal = waveOriginal,
                WaveformStego = waveStego,
                WaveformDifference = waveDiff,
                IsCompatible = true
            };
        }
    }
}
