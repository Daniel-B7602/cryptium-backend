using System.Security.Cryptography;
using System.Text;

namespace cryptium_backend.Services
{
    public static class CryptoTests
    {
        public static int RunAll()
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" CRYPTIUM .NET 8 CRYPTOGRAPHIC TEST SUITE");
            Console.WriteLine("============================================================");

            var cryptoService = new CryptoService();
            var fileCryptoService = new FileCryptoService();

            int passed = 0;
            int failed = 0;

            void AssertTest(string name, bool condition, string details = "")
            {
                if (condition)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  [PASS] {name}");
                    Console.ResetColor();
                    passed++;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  [FAIL] {name} - {details}");
                    Console.ResetColor();
                    failed++;
                }
            }

            // ----------------------------------------------------
            // 1. TEXT ENCRYPTION & DECRYPTION (AES, ChaCha20, RSA)
            // ----------------------------------------------------
            Console.WriteLine("\n--- 1. Pruebas de Cifrado y Descifrado de Texto ---");

            string originalText = "¡Hola Cryptium 2026! Mensaje confidencial con tildes, números 12345 y símbolos: #$%&/()=?";
            string keyPass = "ClaveSecretaSuperSegura2026*";

            // 1.1 AES-256
            var aesEnc = cryptoService.EncryptText(originalText, keyPass, "AES");
            var aesDec = cryptoService.DecryptText(aesEnc.EncryptedText!, keyPass, "AES");
            AssertTest("AES-256 Texto: Cifrado y Descifrado idéntico", aesDec.DecryptedText == originalText);
            AssertTest("AES-256 Texto: Reporta algoritmo AES-256", aesEnc.Algorithm == "AES-256");
            AssertTest("AES-256 Texto: Genera IV aleatorio de 16 bytes", aesEnc.NonceOrIvHex?.Length == 32);

            // 1.2 ChaCha20
            var ccEnc = cryptoService.EncryptText(originalText, keyPass, "ChaCha20");
            var ccDec = cryptoService.DecryptText(ccEnc.EncryptedText!, keyPass, "ChaCha20");
            AssertTest("ChaCha20 Texto: Cifrado y Descifrado idéntico", ccDec.DecryptedText == originalText);
            AssertTest("ChaCha20 Texto: Reporta algoritmo ChaCha20", ccEnc.Algorithm == "ChaCha20");
            AssertTest("ChaCha20 Texto: Genera Nonce de 12 bytes (24 hex)", ccEnc.NonceOrIvHex?.Length == 24);

            // 1.3 ChaCha20 Nonce Uniqueness
            var ccEnc2 = cryptoService.EncryptText(originalText, keyPass, "ChaCha20");
            AssertTest("ChaCha20 Texto: Nonce único por operación (no reutilización)", ccEnc.NonceOrIvHex != ccEnc2.NonceOrIvHex);
            AssertTest("ChaCha20 Texto: Criptogramas distintos con misma clave y texto gracias al nonce", ccEnc.EncryptedText != ccEnc2.EncryptedText);

            // 1.4 RSA Key Generation & Direct Encryption
            var rsaKeys = cryptoService.GenerateRsaKeyPair(2048);
            AssertTest("RSA: Clave Pública en formato PEM", rsaKeys.PublicKey.Contains("BEGIN PUBLIC KEY"));
            AssertTest("RSA: Clave Privada en formato PEM", rsaKeys.PrivateKey.Contains("BEGIN PRIVATE KEY"));

            var rsaEnc = cryptoService.EncryptText(originalText, rsaKeys.PublicKey, "RSA");
            var rsaDec = cryptoService.DecryptText(rsaEnc.EncryptedText!, rsaKeys.PrivateKey, "RSA");
            AssertTest("RSA Texto Corto: Cifrado directo con Clave Pública y descifrado con Clave Privada", rsaDec.DecryptedText == originalText);
            AssertTest("RSA Texto Corto: Reporta algoritmo RSA", rsaEnc.Algorithm == "RSA");

            // 1.5 RSA Hybrid Text Encryption (> 190 bytes)
            var sb = new StringBuilder();
            for (int i = 0; i < 40; i++) sb.Append($"Bloque_{i}_de_datos_confidenciales_cryptium_");
            string longText = sb.ToString(); // > 1500 caracteres, mucho más del límite OAEP de 190 bytes

            var rsaLongEnc = cryptoService.EncryptText(longText, rsaKeys.PublicKey, "RSA");
            var rsaLongDec = cryptoService.DecryptText(rsaLongEnc.EncryptedText!, rsaKeys.PrivateKey, "RSA");
            AssertTest("RSA Texto Largo (>190 bytes): Cifrado Híbrido transparente y recuperación exacta", rsaLongDec.DecryptedText == longText);
            AssertTest("RSA Texto Largo: Reporta sobre digital híbrido", rsaLongEnc.Algorithm.Contains("Híbrido"));

            // ----------------------------------------------------
            // 2. FILE ENCRYPTION & DECRYPTION (AES, ChaCha20, RSA Híbrido)
            // ----------------------------------------------------
            Console.WriteLine("\n--- 2. Pruebas de Cifrado y Descifrado de Archivos ---");

            byte[] fileBytes = new byte[100 * 1024]; // 100 KB
            RandomNumberGenerator.Fill(fileBytes);

            // 2.1 AES-256 File
            byte[] aesFileEnc = fileCryptoService.EncryptFile(fileBytes, keyPass, "AES");
            byte[] aesFileDec = fileCryptoService.DecryptFile(aesFileEnc, keyPass, "AES");
            AssertTest("AES-256 Archivo (100 KB): Recuperación byte a byte idéntica", fileBytes.AsSpan().SequenceEqual(aesFileDec));

            // 2.2 ChaCha20 File
            byte[] ccFileEnc = fileCryptoService.EncryptFile(fileBytes, keyPass, "ChaCha20");
            byte[] ccFileDec = fileCryptoService.DecryptFile(ccFileEnc, keyPass, "ChaCha20");
            AssertTest("ChaCha20 Archivo (100 KB): Recuperación byte a byte idéntica", fileBytes.AsSpan().SequenceEqual(ccFileDec));

            // 2.3 RSA Hybrid File (100 KB, exceeds RSA single-block limit by >500x)
            byte[] rsaFileEnc = fileCryptoService.EncryptFile(fileBytes, rsaKeys.PublicKey, "RSA");
            byte[] rsaFileDec = fileCryptoService.DecryptFile(rsaFileEnc, rsaKeys.PrivateKey, "RSA");
            AssertTest("RSA Híbrido Archivo (100 KB): Sobre digital y recuperación byte a byte idéntica", fileBytes.AsSpan().SequenceEqual(rsaFileDec));

            // ----------------------------------------------------
            // 3. ARCHIVOS AES ANTERIORES (RETROCOMPATIBILIDAD)
            // ----------------------------------------------------
            Console.WriteLine("\n--- 3. Compatibilidad con Archivos AES Anteriores (Legacy) ---");

            // Simular archivo generado por la versión anterior de Cryptium:
            // [16 bytes IV][AES-CBC ciphertext with PKCS7] sin encabezado V2
            byte[] legacySha = SHA256.HashData(Encoding.UTF8.GetBytes(keyPass));
            using var legacyAes = Aes.Create();
            legacyAes.Key = legacySha;
            legacyAes.GenerateIV();
            using var legacyEnc = legacyAes.CreateEncryptor();
            byte[] legacyCipher = legacyEnc.TransformFinalBlock(fileBytes, 0, fileBytes.Length);

            byte[] legacyRawFile = new byte[16 + legacyCipher.Length];
            Buffer.BlockCopy(legacyAes.IV, 0, legacyRawFile, 0, 16);
            Buffer.BlockCopy(legacyCipher, 0, legacyRawFile, 16, legacyCipher.Length);

            byte[] legacyDecrypted = fileCryptoService.DecryptFile(legacyRawFile, keyPass, "AES");
            AssertTest("Archivos AES Anteriores (Sin encabezado V2): Descifrado retrocompatible 100% exacto", fileBytes.AsSpan().SequenceEqual(legacyDecrypted));

            // ----------------------------------------------------
            // 4. PRUEBAS DE CLAVES INCORRECTAS
            // ----------------------------------------------------
            Console.WriteLine("\n--- 4. Pruebas de Claves Incorrectas ---");

            string wrongKey = "ClaveCompletamenteIncorrecta!";

            // 4.1 AES Text with Wrong Key
            bool aesWrongKeyCaught = false;
            try
            {
                cryptoService.DecryptText(aesEnc.EncryptedText!, wrongKey, "AES");
            }
            catch (CryptographicException)
            {
                aesWrongKeyCaught = true;
            }
            AssertTest("AES Texto: Rechaza clave incorrecta con excepción criptográfica", aesWrongKeyCaught);

            // 4.2 AES File with Wrong Key
            bool aesFileWrongKeyCaught = false;
            try
            {
                fileCryptoService.DecryptFile(aesFileEnc, wrongKey, "AES");
            }
            catch (CryptographicException)
            {
                aesFileWrongKeyCaught = true;
            }
            AssertTest("AES Archivo: Rechaza clave incorrecta", aesFileWrongKeyCaught);

            // 4.3 RSA File with Wrong Private Key
            var otherRsaKeys = cryptoService.GenerateRsaKeyPair(2048);
            bool rsaFileWrongKeyCaught = false;
            try
            {
                fileCryptoService.DecryptFile(rsaFileEnc, otherRsaKeys.PrivateKey, "RSA");
            }
            catch (CryptographicException)
            {
                rsaFileWrongKeyCaught = true;
            }
            AssertTest("RSA Archivo: Rechaza clave privada no correspondiente al par público", rsaFileWrongKeyCaught);

            // 4.4 RSA Text with Wrong Private Key
            bool rsaTextWrongKeyCaught = false;
            try
            {
                cryptoService.DecryptText(rsaEnc.EncryptedText!, otherRsaKeys.PrivateKey, "RSA");
            }
            catch (CryptographicException)
            {
                rsaTextWrongKeyCaught = true;
            }
            AssertTest("RSA Texto: Rechaza clave privada no coincidente", rsaTextWrongKeyCaught);

            // ----------------------------------------------------
            // 5. PRUEBAS DE ENTRADAS Y ARCHIVOS INVÁLIDOS
            // ----------------------------------------------------
            Console.WriteLine("\n--- 5. Pruebas de Entradas Inválidas ---");

            // 5.1 Empty text
            bool emptyTextCaught = false;
            try { cryptoService.EncryptText("", "clave123", "AES"); }
            catch (ArgumentException) { emptyTextCaught = true; }
            AssertTest("Validación: Rechaza texto vacío al cifrar", emptyTextCaught);

            // 5.2 Empty key
            bool emptyKeyCaught = false;
            try { cryptoService.EncryptText("hola", "", "AES"); }
            catch (ArgumentException) { emptyKeyCaught = true; }
            AssertTest("Validación: Rechaza clave vacía al cifrar", emptyKeyCaught);

            // 5.3 Invalid RSA PEM
            bool invalidPemCaught = false;
            string invalidPemMsg = "";
            try { cryptoService.EncryptText("hola", "CLAVE_NO_VALIDA_PEM", "RSA"); }
            catch (ArgumentException ex) { invalidPemCaught = true; invalidPemMsg = ex.Message; }
            AssertTest("Validación: Rechaza clave RSA con formato PEM corrupto/inválido", invalidPemCaught);
            AssertTest("Validación: Mensaje amigable sin fugas técnicas ASN.1/OpenSSL", !invalidPemMsg.Contains("ASN1") && !invalidPemMsg.Contains("No supported key formats"));

            // 5.4 Inverted RSA Keys (Private in Encrypt / Public in Decrypt)
            bool privateInEncryptCaught = false;
            string privateInEncryptMsg = "";
            try { cryptoService.EncryptText("hola", rsaKeys.PrivateKey, "RSA"); }
            catch (ArgumentException ex) { privateInEncryptCaught = true; privateInEncryptMsg = ex.Message; }
            AssertTest("Validación: Detecta y rechaza uso de Clave Privada para cifrar", privateInEncryptCaught && privateInEncryptMsg.Contains("Has introducido una Clave Privada"));

            bool publicInDecryptCaught = false;
            string publicInDecryptMsg = "";
            try { cryptoService.DecryptText(rsaEnc.EncryptedText!, rsaKeys.PublicKey, "RSA"); }
            catch (ArgumentException ex) { publicInDecryptCaught = true; publicInDecryptMsg = ex.Message; }
            AssertTest("Validación: Detecta y rechaza uso de Clave Pública para descifrar", publicInDecryptCaught && publicInDecryptMsg.Contains("Has introducido una Clave Pública"));

            // 5.5 Empty File
            bool emptyFileCaught = false;
            try { fileCryptoService.EncryptFile(Array.Empty<byte>(), "clave", "AES"); }
            catch (ArgumentException) { emptyFileCaught = true; }
            AssertTest("Validación: Rechaza archivo vacío (0 bytes)", emptyFileCaught);

            Console.WriteLine("\n============================================================");
            if (failed == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($" RESUMEN: {passed} PRUEBAS PASADAS / {failed} FALLIDAS (100% ÉXITO)");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($" RESUMEN: {passed} PRUEBAS PASADAS / {failed} FALLIDAS");
                Console.ResetColor();
            }
            Console.WriteLine("============================================================");

            return failed;
        }
    }
}
