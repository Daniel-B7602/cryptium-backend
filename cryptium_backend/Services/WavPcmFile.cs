using System.Text;

namespace cryptium_backend.Services
{
    public class WavPcmFile
    {
        public ushort AudioFormat { get; private set; }
        public ushort Channels { get; private set; }
        public uint SampleRate { get; private set; }
        public uint ByteRate { get; private set; }
        public ushort BlockAlign { get; private set; }
        public ushort BitsPerSample { get; private set; }

        public int DataChunkOffset { get; private set; }
        public int DataChunkSize { get; private set; }

        public byte[] RawBytes { get; private set; } = Array.Empty<byte>();

        public long TotalSamples => BitsPerSample > 0 ? (DataChunkSize / (BitsPerSample / 8)) : 0;

        public double DurationSeconds
        {
            get
            {
                if (Channels == 0 || SampleRate == 0 || BitsPerSample == 0) return 0;
                long bytesPerSec = (long)SampleRate * Channels * (BitsPerSample / 8);
                return bytesPerSec > 0 ? (double)DataChunkSize / bytesPerSec : 0;
            }
        }

        public static WavPcmFile Parse(byte[] fileBytes)
        {
            if (fileBytes == null || fileBytes.Length < 44)
            {
                throw new ArgumentException("El archivo es demasiado pequeño o está incompleto para ser un audio WAV válido.");
            }

            string riff = Encoding.ASCII.GetString(fileBytes, 0, 4);
            string wave = Encoding.ASCII.GetString(fileBytes, 8, 4);

            if (riff != "RIFF" || wave != "WAVE")
            {
                throw new InvalidOperationException("El archivo no tiene una cabecera RIFF/WAVE válida.");
            }

            var wav = new WavPcmFile
            {
                RawBytes = fileBytes
            };

            int offset = 12;
            bool fmtFound = false;
            bool dataFound = false;

            while (offset + 8 <= fileBytes.Length)
            {
                string chunkId = Encoding.ASCII.GetString(fileBytes, offset, 4);
                uint chunkSize = BitConverter.ToUInt32(fileBytes, offset + 4);
                offset += 8;

                if (chunkId == "fmt ")
                {
                    if (offset + 16 > fileBytes.Length)
                    {
                        throw new InvalidOperationException("Encabezado 'fmt ' incompleto o dañado.");
                    }

                    wav.AudioFormat = BitConverter.ToUInt16(fileBytes, offset);
                    wav.Channels = BitConverter.ToUInt16(fileBytes, offset + 2);
                    wav.SampleRate = BitConverter.ToUInt32(fileBytes, offset + 4);
                    wav.ByteRate = BitConverter.ToUInt32(fileBytes, offset + 8);
                    wav.BlockAlign = BitConverter.ToUInt16(fileBytes, offset + 12);
                    wav.BitsPerSample = BitConverter.ToUInt16(fileBytes, offset + 14);

                    if (wav.AudioFormat != 1)
                    {
                        throw new InvalidOperationException(
                            $"Formato de compresión ({wav.AudioFormat}) no compatible. Sólo se admite WAV PCM sin compresión (Formato 1).");
                    }

                    if (wav.BitsPerSample != 16 && wav.BitsPerSample != 8)
                    {
                        throw new InvalidOperationException(
                            $"Profundidad de {wav.BitsPerSample} bits no compatible. Sólo se admiten archivos PCM de 16 u 8 bits.");
                    }

                    if (wav.Channels == 0)
                    {
                        throw new InvalidOperationException("El número de canales debe ser mayor que cero.");
                    }

                    fmtFound = true;
                }
                else if (chunkId == "data")
                {
                    wav.DataChunkOffset = offset;
                    // Clamp to actual available data to avoid reading out of bounds
                    int availableData = Math.Max(0, fileBytes.Length - offset);
                    wav.DataChunkSize = (int)Math.Min((long)chunkSize, availableData);
                    dataFound = true;
                }

                // Advance to next chunk aligned to 2 bytes (standard RIFF chunk padding)
                long nextOffset = (long)offset + chunkSize;
                if ((chunkSize & 1) == 1)
                {
                    nextOffset++;
                }

                if (nextOffset > fileBytes.Length || nextOffset <= offset)
                {
                    break;
                }

                offset = (int)nextOffset;
            }

            if (!fmtFound)
            {
                throw new InvalidOperationException("No se encontró el bloque de formato 'fmt ' en el archivo WAV.");
            }

            if (!dataFound || wav.DataChunkSize <= 0)
            {
                throw new InvalidOperationException("No se encontró el bloque de datos de audio 'data' en el archivo WAV.");
            }

            return wav;
        }

        public byte[] CloneRawBytes()
        {
            byte[] copy = new byte[RawBytes.Length];
            Buffer.BlockCopy(RawBytes, 0, copy, 0, RawBytes.Length);
            return copy;
        }
    }
}
