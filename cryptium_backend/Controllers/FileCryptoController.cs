using cryptium_backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace cryptium_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class FileCryptoController : ControllerBase
    {
        private readonly FileCryptoService _fileCryptoService;

        public FileCryptoController(FileCryptoService fileCryptoService)
        {
            _fileCryptoService = fileCryptoService;
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt(
            IFormFile file,
            [FromForm] string key)
        {
            if (file == null || file.Length == 0)
                return BadRequest("Debes seleccionar un archivo.");

            if (string.IsNullOrWhiteSpace(key))
                return BadRequest("La clave no puede estar vacía.");

            using MemoryStream memoryStream = new();

            file.CopyTo(memoryStream);

            byte[] encrypted = _fileCryptoService.EncryptFile(
                memoryStream.ToArray(),
                key
            );

            string fileName = file.FileName + ".cryptium";

            return File(
                encrypted,
                "application/octet-stream",
                fileName
            );
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt(
            IFormFile file,
            [FromForm] string key)
        {
            if (file == null || file.Length == 0)
                return BadRequest("Debes seleccionar un archivo.");

            if (string.IsNullOrWhiteSpace(key))
                return BadRequest("La clave no puede estar vacía.");

            try
            {
                using MemoryStream memoryStream = new();

                file.CopyTo(memoryStream);

                byte[] decrypted = _fileCryptoService.DecryptFile(
                    memoryStream.ToArray(),
                    key
                );

                string fileName = file.FileName;

                if (fileName.EndsWith(".cryptium"))
                {
                    fileName = fileName[..^9];
                }

                return File(
                    decrypted,
                    "application/octet-stream",
                    fileName
                );
            }
            catch
            {
                return BadRequest(
                    "No se pudo descifrar el archivo. " +
                    "Verifica la clave y el archivo."
                );
            }
        }
    }
}