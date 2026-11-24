using cryptium_backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace cryptium_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileCryptoController : ControllerBase
    {
        private readonly FileCryptoService _fileCryptoService;
        private readonly CryptoService _cryptoService;

        public FileCryptoController(FileCryptoService fileCryptoService, CryptoService cryptoService)
        {
            _fileCryptoService = fileCryptoService;
            _cryptoService = cryptoService;
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt(
            IFormFile file,
            [FromForm] string key,
            [FromForm] string? algorithm = "AES")
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "Debes seleccionar un archivo para cifrar." });

            if (string.IsNullOrWhiteSpace(key))
                return BadRequest(new { message = "La clave no puede estar vacía." });

            try
            {
                using MemoryStream memoryStream = new();
                file.CopyTo(memoryStream);

                byte[] encrypted = _fileCryptoService.EncryptFile(
                    memoryStream.ToArray(),
                    key,
                    algorithm ?? "AES"
                );

                string fileName = file.FileName + ".cryptium";

                return File(
                    encrypted,
                    "application/octet-stream",
                    fileName
                );
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error durante el cifrado del archivo: {ex.Message}" });
            }
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt(
            IFormFile file,
            [FromForm] string key,
            [FromForm] string? algorithm = "AES")
        {
            if (file == null || file.Length == 0)
                return BadRequest(new { message = "Debes seleccionar un archivo para descifrar." });

            if (string.IsNullOrWhiteSpace(key))
                return BadRequest(new { message = "La clave no puede estar vacía." });

            try
            {
                using MemoryStream memoryStream = new();
                file.CopyTo(memoryStream);

                byte[] decrypted = _fileCryptoService.DecryptFile(
                    memoryStream.ToArray(),
                    key,
                    algorithm ?? "AES"
                );

                string fileName = file.FileName;
                if (fileName.EndsWith(".cryptium", StringComparison.OrdinalIgnoreCase))
                {
                    fileName = fileName[..^9];
                }
                else
                {
                    fileName = "descifrado_" + fileName;
                }

                return File(
                    decrypted,
                    "application/octet-stream",
                    fileName
                );
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"No se pudo descifrar el archivo. {ex.Message}" });
            }
        }

        [HttpGet("rsa/generate-keys")]
        [HttpPost("rsa/generate-keys")]
        public IActionResult GenerateRsaKeys([FromQuery] int keySize = 2048)
        {
            try
            {
                var keyPair = _cryptoService.GenerateRsaKeyPair(keySize);
                return Ok(keyPair);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error generando par de claves RSA: {ex.Message}" });
            }
        }
    }
}
