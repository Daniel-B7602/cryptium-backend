using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using cryptium_backend.Models;

namespace cryptium_backend.Services
{
    public class CryptoService
    {
        private static readonly byte[] RsaHybridMagic = Encoding.ASCII.GetBytes("RSAH"); // 4 bytes

        #region Métodos de Compatibilidad Heredada
        public string Encrypt(string plainText, string key)
        {
            return EncryptText(plainText, key, "AES").EncryptedText!;
        }

        public string Decrypt(string encryptedText, string key)
        {
            return DecryptText(encryptedText, key, "AES").DecryptedText!;
        }
        #endregion

        #region Generación de Claves RSA
        public RsaKeyPairResponse GenerateRsaKeyPair(int keySize = 2048)
        {
            if (keySize < 2048) keySize = 2048;

            using RSA rsa = RSA.Create(keySize);
            string publicKey = rsa.ExportSubjectPublicKeyInfoPem();
            string privateKey = rsa.ExportPkcs8PrivateKeyPem();

            return new RsaKeyPairResponse
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
                KeySize = keySize
            };
        }
        #endregion

        #region Cifrado de Texto Multialgoritmo
        public CryptoResponse EncryptText(string plainText, string key, string algorithm = "AES")
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("El texto a cifrar no puede estar vacío.", nameof(plainText));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("La clave no puede estar vacía.", nameof(key));

            string normAlgo = NormalizeAlgorithm(algorithm);

            switch (normAlgo)
            {
                case "AES":
                    return EncryptAes(plainText, key);

                case "CHACHA20":
                    return EncryptChaCha20(plainText, key);

                case "RSA":
                    return EncryptRsa(plainText, key);

                default:
                    throw new NotSupportedException($"El algoritmo '{algorithm}' no está soportado. Selecciona AES-256, ChaCha20 o RSA.");
            }
        }

        public CryptoResponse DecryptText(string encryptedText, string key, string algorithm = "AES")
        {
            if (string.IsNullOrWhiteSpace(encryptedText))
                throw new ArgumentException("El texto cifrado no puede estar vacío.", nameof(encryptedText));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("La clave no puede estar vacía.", nameof(key));

            string normAlgo = NormalizeAlgorithm(algorithm);

            switch (normAlgo)
            {
                case "AES":
                    return DecryptAes(encryptedText, key);

                case "CHACHA20":
                    return DecryptChaCha20(encryptedText, key);

                case "RSA":
                    return DecryptRsa(encryptedText, key);

                default:
                    throw new NotSupportedException($"El algoritmo '{algorithm}' no está soportado. Selecciona AES-256, ChaCha20 o RSA.");
            }
        }
        #endregion

        #region Implementación AES-256
        private static CryptoResponse EncryptAes(string plainText, string key)
        {
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();
            aes.Key = keyBytes;
            aes.GenerateIV();

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            byte[] result = new byte[aes.IV.Length + encryptedBytes.Length];
            Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

            return new CryptoResponse
            {
                EncryptedText = Convert.ToBase64String(result),
                Algorithm = "AES-256",
                NonceOrIvHex = Convert.ToHexString(aes.IV),
                Details = "Cifrado por bloques AES-256 en modo CBC con relleno PKCS#7 y vector de inicialización (IV) de 16 bytes."
            };
        }

        private static CryptoResponse DecryptAes(string encryptedText, string key)
        {
            byte[] encryptedData;
            try
            {
                encryptedData = Convert.FromBase64String(encryptedText);
            }
            catch (FormatException)
            {
                throw new ArgumentException("El texto cifrado no tiene un formato Base64 válido.");
            }

            if (encryptedData.Length < 16)
                throw new ArgumentException("El texto cifrado es demasiado corto para contener un IV válido de AES.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            using Aes aes = Aes.Create();
            aes.Key = keyBytes;

            byte[] iv = new byte[16];
            byte[] cipherText = new byte[encryptedData.Length - 16];

            Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
            Buffer.BlockCopy(encryptedData, 16, cipherText, 0, cipherText.Length);

            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);

                return new CryptoResponse
                {
                    DecryptedText = Encoding.UTF8.GetString(decryptedBytes),
                    Algorithm = "AES-256",
                    NonceOrIvHex = Convert.ToHexString(iv),
                    Details = "Descifrado exitoso con AES-256-CBC."
                };
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("No se pudo descifrar con AES-256. Verifica que la clave introducida sea exactamente la misma.");
            }
        }
        #endregion

        #region Implementación ChaCha20
        private static CryptoResponse EncryptChaCha20(string plainText, string key)
        {
            // Clave segura de 256 bits derivada de la contraseña
            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            // Nonce aleatorio de 96 bits (12 bytes) único para cada operación
            byte[] nonce = RandomNumberGenerator.GetBytes(ChaCha20Engine.NonceSize);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = ChaCha20Engine.Process(plainBytes, keyBytes, nonce, 1);

            // Contenedor: [12 bytes Nonce][Ciphertext]
            byte[] result = new byte[ChaCha20Engine.NonceSize + cipherBytes.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, ChaCha20Engine.NonceSize);
            Buffer.BlockCopy(cipherBytes, 0, result, ChaCha20Engine.NonceSize, cipherBytes.Length);

            return new CryptoResponse
            {
                EncryptedText = Convert.ToBase64String(result),
                Algorithm = "ChaCha20",
                NonceOrIvHex = Convert.ToHexString(nonce),
                Details = "Cifrador de flujo ChaCha20 puro (RFC 8439) con clave de 256 bits y nonce de 96 bits. No autenticado (sin MAC Poly1305)."
            };
        }

        private static CryptoResponse DecryptChaCha20(string encryptedText, string key)
        {
            byte[] encryptedData;
            try
            {
                encryptedData = Convert.FromBase64String(encryptedText);
            }
            catch (FormatException)
            {
                throw new ArgumentException("El texto cifrado no tiene un formato Base64 válido.");
            }

            if (encryptedData.Length < ChaCha20Engine.NonceSize)
                throw new ArgumentException("El texto cifrado es demasiado corto para contener un nonce ChaCha20 de 12 bytes.");

            byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));

            byte[] nonce = new byte[ChaCha20Engine.NonceSize];
            byte[] cipherBytes = new byte[encryptedData.Length - ChaCha20Engine.NonceSize];

            Buffer.BlockCopy(encryptedData, 0, nonce, 0, ChaCha20Engine.NonceSize);
            Buffer.BlockCopy(encryptedData, ChaCha20Engine.NonceSize, cipherBytes, 0, cipherBytes.Length);

            byte[] plainBytes = ChaCha20Engine.Process(cipherBytes, keyBytes, nonce, 1);

            return new CryptoResponse
            {
                DecryptedText = Encoding.UTF8.GetString(plainBytes),
                Algorithm = "ChaCha20",
                NonceOrIvHex = Convert.ToHexString(nonce),
                Details = "Descifrado exitoso con ChaCha20 (cifrador de flujo no autenticado)."
            };
        }
        #endregion

        #region Implementación RSA
        internal static void LoadRsaPublicKey(RSA rsa, string publicKeyPem)
        {
            if (string.IsNullOrWhiteSpace(publicKeyPem))
                throw new ArgumentException("Debes proporcionar una Clave Pública RSA en formato PEM.");

            string cleanPem = publicKeyPem.Trim();

            if (cleanPem.Contains("BEGIN PRIVATE KEY") || cleanPem.Contains("BEGIN RSA PRIVATE KEY"))
            {
                throw new ArgumentException("Has introducido una Clave Privada en lugar de una Clave Pública. En el cifrado asimétrico RSA, los mensajes se cifran con la Clave Pública del destinatario. La Clave Privada se utiliza únicamente para descifrar.");
            }

            if (!cleanPem.Contains("-----BEGIN PUBLIC KEY-----") || !cleanPem.Contains("-----END PUBLIC KEY-----"))
            {
                throw new ArgumentException("La clave pública proporcionada no tiene un formato PEM válido. Debe comenzar con '-----BEGIN PUBLIC KEY-----' y finalizar con '-----END PUBLIC KEY-----'.");
            }

            try
            {
                rsa.ImportFromPem(cleanPem);
            }
            catch (Exception)
            {
                throw new ArgumentException("La clave pública contiene caracteres o datos corruptos en su codificación Base64. Verifica que se haya copiado íntegramente sin alterar los caracteres.");
            }
        }

        internal static void LoadRsaPrivateKey(RSA rsa, string privateKeyPem)
        {
            if (string.IsNullOrWhiteSpace(privateKeyPem))
                throw new ArgumentException("Debes proporcionar una Clave Privada RSA en formato PEM.");

            string cleanPem = privateKeyPem.Trim();

            if (cleanPem.Contains("BEGIN PUBLIC KEY"))
            {
                throw new ArgumentException("Has introducido una Clave Pública en lugar de una Clave Privada. Para descifrar mensajes cifrados con RSA debes utilizar la Clave Privada correspondiente.");
            }

            bool hasBeginPrivate = cleanPem.Contains("-----BEGIN PRIVATE KEY-----") || cleanPem.Contains("-----BEGIN RSA PRIVATE KEY-----");
            bool hasEndPrivate = cleanPem.Contains("-----END PRIVATE KEY-----") || cleanPem.Contains("-----END RSA PRIVATE KEY-----");

            if (!hasBeginPrivate || !hasEndPrivate)
            {
                throw new ArgumentException("La clave privada proporcionada no tiene un formato PEM válido. Debe comenzar con '-----BEGIN PRIVATE KEY-----' (o '-----BEGIN RSA PRIVATE KEY-----') y finalizar con '-----END PRIVATE KEY-----'.");
            }

            try
            {
                rsa.ImportFromPem(cleanPem);
            }
            catch (Exception)
            {
                throw new ArgumentException("La clave privada contiene caracteres o datos corruptos en su codificación Base64. Verifica que se haya copiado íntegramente sin alterar los caracteres.");
            }
        }

        private static CryptoResponse EncryptRsa(string plainText, string publicKeyPem)
        {
            using RSA rsa = RSA.Create();
            LoadRsaPublicKey(rsa, publicKeyPem);

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Para RSA-2048 con OAEP-SHA256, el tamaño máximo de texto en claro es:
            // 256 bytes (módulo) - 2 * 32 (longitud hash) - 2 = 190 bytes.
            int maxOaepPlaintext = (rsa.KeySize / 8) - (2 * 32) - 2;

            if (plainBytes.Length <= maxOaepPlaintext)
            {
                // Cifrado directo con clave pública RSA y relleno OAEP con SHA-256
                byte[] cipherBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);

                return new CryptoResponse
                {
                    EncryptedText = Convert.ToBase64String(cipherBytes),
                    Algorithm = "RSA",
                    Details = $"Cifrado asimétrico directo con Clave Pública RSA ({rsa.KeySize} bits) y esquema de relleno seguro OAEP-SHA256."
                };
            }
            else
            {
                // Para textos que excedan el límite de OAEP, se utiliza Cifrado Híbrido:
                // RSA protege una clave simétrica temporal AES-256, y AES cifra el texto completo.
                byte[] sessionKey = RandomNumberGenerator.GetBytes(32); // 256 bits
                byte[] iv = RandomNumberGenerator.GetBytes(16);

                byte[] encryptedSessionKey = rsa.Encrypt(sessionKey, RSAEncryptionPadding.OaepSHA256);

                using Aes aes = Aes.Create();
                aes.Key = sessionKey;
                aes.IV = iv;

                using ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                // Contenedor híbrido: [4 bytes "RSAH"][2 bytes keyLen][encKey][16 bytes IV][Ciphertext]
                ushort keyLen = (ushort)encryptedSessionKey.Length;
                byte[] container = new byte[4 + 2 + keyLen + 16 + cipherBytes.Length];

                Buffer.BlockCopy(RsaHybridMagic, 0, container, 0, 4);
                BinaryPrimitives.WriteUInt16LittleEndian(container.AsSpan(4, 2), keyLen);
                Buffer.BlockCopy(encryptedSessionKey, 0, container, 6, keyLen);
                Buffer.BlockCopy(iv, 0, container, 6 + keyLen, 16);
                Buffer.BlockCopy(cipherBytes, 0, container, 6 + keyLen + 16, cipherBytes.Length);

                return new CryptoResponse
                {
                    EncryptedText = Convert.ToBase64String(container),
                    Algorithm = "RSA (Híbrido)",
                    NonceOrIvHex = Convert.ToHexString(iv),
                    Details = $"Cifrado Híbrido (RSA-{rsa.KeySize} + AES-256-CBC): la clave pública RSA protege una clave simétrica de sesión de 256 bits, la cual cifra el texto completo."
                };
            }
        }

        private static CryptoResponse DecryptRsa(string encryptedText, string privateKeyPem)
        {
            using RSA rsa = RSA.Create();
            LoadRsaPrivateKey(rsa, privateKeyPem);

            byte[] encryptedData;
            try
            {
                encryptedData = Convert.FromBase64String(encryptedText);
            }
            catch (FormatException)
            {
                throw new ArgumentException("El texto cifrado no tiene un formato Base64 válido.");
            }

            // Verificar si es un sobre digital híbrido (inicia con magic "RSAH")
            bool isHybrid = encryptedData.Length >= 6 &&
                            encryptedData[0] == RsaHybridMagic[0] &&
                            encryptedData[1] == RsaHybridMagic[1] &&
                            encryptedData[2] == RsaHybridMagic[2] &&
                            encryptedData[3] == RsaHybridMagic[3];

            if (isHybrid)
            {
                ushort keyLen = BinaryPrimitives.ReadUInt16LittleEndian(encryptedData.AsSpan(4, 2));
                if (encryptedData.Length < 6 + keyLen + 16)
                    throw new ArgumentException("El paquete híbrido RSA está incompleto o corrupto.");

                byte[] encSessionKey = new byte[keyLen];
                byte[] iv = new byte[16];
                int cipherOffset = 6 + keyLen + 16;
                byte[] cipherBytes = new byte[encryptedData.Length - cipherOffset];

                Buffer.BlockCopy(encryptedData, 6, encSessionKey, 0, keyLen);
                Buffer.BlockCopy(encryptedData, 6 + keyLen, iv, 0, 16);
                Buffer.BlockCopy(encryptedData, cipherOffset, cipherBytes, 0, cipherBytes.Length);

                byte[] sessionKey;
                try
                {
                    sessionKey = rsa.Decrypt(encSessionKey, RSAEncryptionPadding.OaepSHA256);
                }
                catch (CryptographicException)
                {
                    throw new CryptographicException("No se pudo descifrar la clave de sesión RSA. Verifica que la clave privada corresponda a la pública utilizada.");
                }

                using Aes aes = Aes.Create();
                aes.Key = sessionKey;
                aes.IV = iv;

                using ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

                return new CryptoResponse
                {
                    DecryptedText = Encoding.UTF8.GetString(plainBytes),
                    Algorithm = "RSA (Híbrido)",
                    NonceOrIvHex = Convert.ToHexString(iv),
                    Details = "Descifrado híbrido exitoso: Clave privada RSA recuperó la clave simétrica y se descifró el texto completo."
                };
            }
            else
            {
                // Descifrado directo RSA con OAEP-SHA256
                try
                {
                    byte[] plainBytes = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                    return new CryptoResponse
                    {
                        DecryptedText = Encoding.UTF8.GetString(plainBytes),
                        Algorithm = "RSA",
                        Details = "Descifrado asimétrico directo exitoso con Clave Privada RSA y relleno OAEP-SHA256."
                    };
                }
                catch (CryptographicException)
                {
                    throw new CryptographicException("No se pudo descifrar con RSA. Verifica que la clave privada introducida sea correcta y coincida con el par usado para cifrar.");
                }
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
