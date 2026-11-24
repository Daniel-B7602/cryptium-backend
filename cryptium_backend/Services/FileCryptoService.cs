using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace cryptium_backend.Services
{
    public class FileCryptoService
    {
        // Encabezado canónico para archivos Cryptium V2
        // [8 bytes "CRYPTIUM"][1 byte Version 0x02][1 byte Algorithm ID]
        // Algoritmo 0x01: AES-256-CBC (16 bytes IV + Ciphertext)
        // Algoritmo 0x02: ChaCha20 (12 bytes Nonce + Ciphertext)
        // Algoritmo 0x03: RSA Híbrido (2 bytes keyLen + encKey + 16 bytes IV + Ciphertext)
        private static readonly byte[] MagicV2 = Encoding.ASCII.GetBytes("CRYPTIUM");
        private const byte Version2 = 0x02;

        public const byte AlgoIdAes = 0x01;
        public const byte AlgoIdChaCha20 = 0x02;
        public const byte AlgoIdRsaHybrid = 0x03;

        #region Compatibilidad Heredada
        public byte[] EncryptFile(byte[] fileBytes, string key)
        {
            return EncryptFile(fileBytes, key, "AES");
        }

        public byte[] DecryptFile(byte[] encryptedFile, string key)
        {
            return DecryptFile(encryptedFile, key, "AES");
        }
        #endregion

        #region Cifrado de Archivos Multialgoritmo
        public byte[] EncryptFile(byte[] fileBytes, string key, string algorithm = "AES")
        {
            if (fileBytes == null || fileBytes.Length == 0)
                throw new ArgumentException("El archivo a cifrar no puede estar vacío.", nameof(fileBytes));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("La clave no puede estar vacía.", nameof(key));

            string normAlgo = NormalizeAlgorithm(algorithm);

            return normAlgo switch
            {
                "AES" => EncryptAesFile(fileBytes, key),
                "CHACHA20" => EncryptChaCha20File(fileBytes, key),
                "RSA" => EncryptRsaHybridFile(fileBytes, key),
                _ => throw new NotSupportedException($"El algoritmo '{algorithm}' no está soportado para archivos.")
            };
        }

        public byte[] DecryptFile(byte[] encryptedFile, string key, string algorithm = "AES")
        {
            if (encryptedFile == null || encryptedFile.Length == 0)
                throw new ArgumentException("El archivo a descifrar no puede estar vacío.", nameof(encryptedFile));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("La clave no puede estar vacía.", nameof(key));

            // Verificar si el archivo posee el encabezado autodescriptivo Cryptium V2
            bool isV2 = encryptedFile.Length >= 10 &&
                        encryptedFile.AsSpan(0, 8).SequenceEqual(MagicV2) &&
                        encryptedFile[8] == Version2;

            if (isV2)
            {
                byte algoId = encryptedFile[9];
                return algoId switch
                {
                    AlgoIdAes => DecryptAesFileV2(encryptedFile, key),
                    AlgoIdChaCha20 => DecryptChaCha20FileV2(encryptedFile, key),
                    AlgoIdRsaHybrid => DecryptRsaHybridFileV2(encryptedFile, key),
                    _ => throw new NotSupportedException($"Identificador de algoritmo desconocido (0x{algoId:X2}) en el archivo Cryptium.")
                };
            }

            // Archivo heredado de versiones anteriores de Cryptium (o formato plano sin encabezado)
            string normAlgo = NormalizeAlgorithm(algorithm);
            return normAlgo switch
            {
                "CHACHA20" => DecryptChaCha20FileLegacy(encryptedFile, key),
                "RSA" => DecryptRsaHybridFileV2(encryptedFile, key),
                _ => DecryptAesFileLegacy(encryptedFile, key)
            };
        }
        #endregion

        #region Implementación AES-256 para Archivos
        private static byte[] EncryptAesFile(byte[] fileBytes, string key)
        {
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();
            aes.Key = keyBytes;
            aes.GenerateIV();

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] cipherBytes = encryptor.TransformFinalBlock(fileBytes, 0, fileBytes.Length);

            // [8 bytes CRYPTIUM][1 byte Version2][1 byte AlgoIdAes][16 bytes IV][Ciphertext]
            byte[] result = new byte[10 + aes.IV.Length + cipherBytes.Length];
            Buffer.BlockCopy(MagicV2, 0, result, 0, 8);
            result[8] = Version2;
            result[9] = AlgoIdAes;
            Buffer.BlockCopy(aes.IV, 0, result, 10, aes.IV.Length);
            Buffer.BlockCopy(cipherBytes, 0, result, 10 + aes.IV.Length, cipherBytes.Length);

            return result;
        }

        private static byte[] DecryptAesFileV2(byte[] encryptedFile, string key)
        {
            if (encryptedFile.Length < 10 + 16)
                throw new ArgumentException("El archivo cifrado con AES es demasiado corto para contener un IV válido.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();
            aes.Key = keyBytes;

            byte[] iv = new byte[16];
            int cipherLen = encryptedFile.Length - 26;
            byte[] cipherText = new byte[cipherLen];

            Buffer.BlockCopy(encryptedFile, 10, iv, 0, 16);
            Buffer.BlockCopy(encryptedFile, 26, cipherText, 0, cipherLen);

            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(cipherText, 0, cipherLen);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("No se pudo descifrar el archivo con AES-256. Verifica que la clave introducida sea exactamente la misma.");
            }
        }

        private static byte[] DecryptAesFileLegacy(byte[] encryptedFile, string key)
        {
            if (encryptedFile.Length < 16)
                throw new ArgumentException("El archivo es demasiado corto para contener un IV válido de AES.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();
            aes.Key = keyBytes;

            byte[] iv = new byte[16];
            int cipherLen = encryptedFile.Length - 16;
            byte[] cipherText = new byte[cipherLen];

            Buffer.BlockCopy(encryptedFile, 0, iv, 0, 16);
            Buffer.BlockCopy(encryptedFile, 16, cipherText, 0, cipherLen);

            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(cipherText, 0, cipherLen);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("No se pudo descifrar el archivo con AES-256. Verifica la clave ingresada.");
            }
        }
        #endregion

        #region Implementación ChaCha20 para Archivos
        private static byte[] EncryptChaCha20File(byte[] fileBytes, string key)
        {
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            byte[] nonce = RandomNumberGenerator.GetBytes(ChaCha20Engine.NonceSize);

            byte[] cipherBytes = ChaCha20Engine.Process(fileBytes, keyBytes, nonce, 1);

            // [8 bytes CRYPTIUM][1 byte Version2][1 byte AlgoIdChaCha20][12 bytes Nonce][Ciphertext]
            byte[] result = new byte[10 + ChaCha20Engine.NonceSize + cipherBytes.Length];
            Buffer.BlockCopy(MagicV2, 0, result, 0, 8);
            result[8] = Version2;
            result[9] = AlgoIdChaCha20;
            Buffer.BlockCopy(nonce, 0, result, 10, ChaCha20Engine.NonceSize);
            Buffer.BlockCopy(cipherBytes, 0, result, 10 + ChaCha20Engine.NonceSize, cipherBytes.Length);

            return result;
        }

        private static byte[] DecryptChaCha20FileV2(byte[] encryptedFile, string key)
        {
            if (encryptedFile.Length < 10 + ChaCha20Engine.NonceSize)
                throw new ArgumentException("El archivo cifrado con ChaCha20 está truncado o incompleto.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            byte[] nonce = new byte[ChaCha20Engine.NonceSize];
            int cipherLen = encryptedFile.Length - (10 + ChaCha20Engine.NonceSize);
            byte[] cipherBytes = new byte[cipherLen];

            Buffer.BlockCopy(encryptedFile, 10, nonce, 0, ChaCha20Engine.NonceSize);
            Buffer.BlockCopy(encryptedFile, 10 + ChaCha20Engine.NonceSize, cipherBytes, 0, cipherLen);

            return ChaCha20Engine.Process(cipherBytes, keyBytes, nonce, 1);
        }

        private static byte[] DecryptChaCha20FileLegacy(byte[] encryptedFile, string key)
        {
            if (encryptedFile.Length < ChaCha20Engine.NonceSize)
                throw new ArgumentException("El archivo es demasiado corto para contener un nonce ChaCha20.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
            byte[] nonce = new byte[ChaCha20Engine.NonceSize];
            int cipherLen = encryptedFile.Length - ChaCha20Engine.NonceSize;
            byte[] cipherBytes = new byte[cipherLen];

            Buffer.BlockCopy(encryptedFile, 0, nonce, 0, ChaCha20Engine.NonceSize);
            Buffer.BlockCopy(encryptedFile, ChaCha20Engine.NonceSize, cipherBytes, 0, cipherLen);

            return ChaCha20Engine.Process(cipherBytes, keyBytes, nonce, 1);
        }
        #endregion

        #region Implementación RSA Híbrido para Archivos
        private static byte[] EncryptRsaHybridFile(byte[] fileBytes, string publicKeyPem)
        {
            using RSA rsa = RSA.Create();
            CryptoService.LoadRsaPublicKey(rsa, publicKeyPem);

            // 1. Generar clave de sesión simétrica aleatoria de 256 bits y vector IV de 16 bytes
            byte[] sessionKey = RandomNumberGenerator.GetBytes(32);
            byte[] iv = RandomNumberGenerator.GetBytes(16);

            // 2. Cifrar la clave de sesión con la clave pública RSA utilizando OAEP-SHA256
            byte[] encSessionKey = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256);
            ushort keyLen = (ushort)encSessionKey.Length;

            // 3. Cifrar el archivo completo a máxima velocidad con la clave de sesión AES-256-CBC
            using Aes aes = Aes.Create();
            aes.Key = sessionKey;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] cipherBytes = encryptor.TransformFinalBlock(fileBytes, 0, fileBytes.Length);

            // 4. Empaquetar el sobre digital:
            // [8 bytes CRYPTIUM][1 byte Version2][1 byte AlgoIdRsaHybrid]
            // [2 bytes keyLen little-endian][encSessionKey][16 bytes IV][Ciphertext]
            int totalLen = 10 + 2 + keyLen + 16 + cipherBytes.Length;
            byte[] result = new byte[totalLen];

            Buffer.BlockCopy(MagicV2, 0, result, 0, 8);
            result[8] = Version2;
            result[9] = AlgoIdRsaHybrid;
            BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(10, 2), keyLen);
            Buffer.BlockCopy(encSessionKey, 0, result, 12, keyLen);
            Buffer.BlockCopy(iv, 0, result, 12 + keyLen, 16);
            Buffer.BlockCopy(cipherBytes, 0, result, 12 + keyLen + 16, cipherBytes.Length);

            return result;
        }

        private static byte[] DecryptRsaHybridFileV2(byte[] encryptedFile, string privateKeyPem)
        {
            using RSA rsa = RSA.Create();
            CryptoService.LoadRsaPrivateKey(rsa, privateKeyPem);

            int headerOffset = 10;
            // Si no tiene el magic v2, comprobar si tiene el magic RSAH de 4 bytes o inicio directo
            if (encryptedFile.Length >= 6 &&
                encryptedFile[0] == 0x52 && encryptedFile[1] == 0x53 && encryptedFile[2] == 0x41 && encryptedFile[3] == 0x48) // "RSAH"
            {
                headerOffset = 4;
            }

            if (encryptedFile.Length < headerOffset + 2 + 16)
                throw new ArgumentException("El archivo híbrido RSA está incompleto o dañado.");

            ushort keyLen = BinaryPrimitives.ReadUInt16LittleEndian(encryptedFile.AsSpan(headerOffset, 2));
            int keyOffset = headerOffset + 2;
            int ivOffset = keyOffset + keyLen;
            int cipherOffset = ivOffset + 16;

            if (encryptedFile.Length < cipherOffset)
                throw new ArgumentException("El archivo híbrido RSA no contiene suficientes datos para descifrar.");

            byte[] encSessionKey = new byte[keyLen];
            byte[] iv = new byte[16];
            int cipherLen = encryptedFile.Length - cipherOffset;
            byte[] cipherBytes = new byte[cipherLen];

            Buffer.BlockCopy(encryptedFile, keyOffset, encSessionKey, 0, keyLen);
            Buffer.BlockCopy(encryptedFile, ivOffset, iv, 0, 16);
            Buffer.BlockCopy(encryptedFile, cipherOffset, cipherBytes, 0, cipherLen);

            byte[] sessionKey;
            try
            {
                sessionKey = rsa.Decrypt(encSessionKey, RSAEncryptionPadding.OaepSHA256);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("No se pudo descifrar el sobre digital con la Clave Privada RSA. Verifica que la clave corresponda al par con el que fue cifrado el archivo.");
            }

            using Aes aes = Aes.Create();
            aes.Key = sessionKey;
            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(cipherBytes, 0, cipherLen);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Error al descifrar el contenido del archivo simétrico. El archivo podría estar corrupto.");
            }
        }
        #endregion

        private static string NormalizeAlgorithm(string algorithm)
        {
            string clean = (algorithm ?? "AES").Trim().ToUpperInvariant();
            if (clean.Contains("CHACHA")) return "CHACHA20";
            if (clean.Contains("RSA")) return "RSA";
            return "AES";
        }
    }
}
