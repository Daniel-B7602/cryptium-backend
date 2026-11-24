using System.Buffers.Binary;
using System.Numerics;

namespace cryptium_backend.Services
{
    /// <summary>
    /// Implementación pura del cifrador de flujo ChaCha20 según RFC 8439 (IETF).
    /// Utiliza clave de 256 bits (32 bytes), nonce de 96 bits (12 bytes) y contador de 32 bits.
    /// Importante: ChaCha20 es un cifrador de flujo simétrico puro no autenticado.
    /// </summary>
    public static class ChaCha20Engine
    {
        public const int KeySize = 32;    // 256 bits
        public const int NonceSize = 12;  // 96 bits
        public const int BlockSize = 64;  // 512 bits por bloque

        public static byte[] Process(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint initialCounter = 1)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"La clave debe tener exactamente {KeySize} bytes (256 bits).", nameof(key));

            if (nonce.Length != NonceSize)
                throw new ArgumentException($"El nonce debe tener exactamente {NonceSize} bytes (96 bits).", nameof(nonce));

            byte[] output = new byte[input.Length];
            Process(input, output, key, nonce, initialCounter);
            return output;
        }

        public static void Process(ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint initialCounter = 1)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"La clave debe tener exactamente {KeySize} bytes (256 bits).", nameof(key));

            if (nonce.Length != NonceSize)
                throw new ArgumentException($"El nonce debe tener exactamente {NonceSize} bytes (96 bits).", nameof(nonce));

            if (output.Length < input.Length)
                throw new ArgumentException("El búfer de salida es menor que la entrada.", nameof(output));

            // Matriz de estado inicial (16 palabras de 32 bits)
            uint[] state = new uint[16];

            // Constantes ("expand 32-byte k")
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            // Clave (8 palabras de 32 bits en little-endian)
            for (int i = 0; i < 8; i++)
            {
                state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
            }

            // Nonce (3 palabras de 32 bits en little-endian)
            state[13] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4));
            state[14] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4));
            state[15] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));

            uint counter = initialCounter;
            Span<byte> keyStream = stackalloc byte[BlockSize];

            int offset = 0;
            while (offset < input.Length)
            {
                // Configurar contador del bloque actual
                state[12] = counter;

                // Generar bloque de flujo de claves (64 bytes)
                GenerateBlock(state, keyStream);

                int bytesToXor = Math.Min(BlockSize, input.Length - offset);
                for (int i = 0; i < bytesToXor; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ keyStream[i]);
                }

                offset += bytesToXor;
                counter++;
            }
        }

        private static void GenerateBlock(uint[] state, Span<byte> output)
        {
            Span<uint> x = stackalloc uint[16];
            state.CopyTo(x);

            // 10 iteraciones de 2 rondas (20 rondas en total)
            for (int i = 0; i < 10; i++)
            {
                // Ronda de columnas
                QuarterRound(ref x[0], ref x[4], ref x[8], ref x[12]);
                QuarterRound(ref x[1], ref x[5], ref x[9], ref x[13]);
                QuarterRound(ref x[2], ref x[6], ref x[10], ref x[14]);
                QuarterRound(ref x[3], ref x[7], ref x[11], ref x[15]);

                // Ronda diagonal
                QuarterRound(ref x[0], ref x[5], ref x[10], ref x[15]);
                QuarterRound(ref x[1], ref x[6], ref x[11], ref x[12]);
                QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);
                QuarterRound(ref x[3], ref x[4], ref x[9], ref x[14]);
            }

            // Sumar estado original a los resultados de las rondas
            for (int i = 0; i < 16; i++)
            {
                uint word = x[i] + state[i];
                BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4, 4), word);
            }
        }

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 16);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 12);
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 8);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 7);
        }
    }
}
