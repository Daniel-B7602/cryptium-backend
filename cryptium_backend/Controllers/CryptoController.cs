using cryptium_backend.Models;
using cryptium_backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace cryptium_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CryptoController : ControllerBase
    {
        private readonly CryptoService _cryptoService;

        public CryptoController(CryptoService cryptoService)
        {
            _cryptoService = cryptoService;
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt([FromBody] CryptoRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest("El texto no puede estar vacío.");

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest("La clave no puede estar vacía.");

            string encrypted = _cryptoService.Encrypt(
                request.Text,
                request.Key
            );

            return Ok(new
            {
                encryptedText = encrypted
            });
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt([FromBody] CryptoRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest("El texto cifrado no puede estar vacío.");

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest("La clave no puede estar vacía.");

            try
            {
                string decrypted = _cryptoService.Decrypt(
                    request.Text,
                    request.Key
                );

                return Ok(new
                {
                    decryptedText = decrypted
                });
            }
            catch
            {
                return BadRequest(
                    "No se pudo descifrar. Verifica la clave y el texto."
                );
            }
        }
    }
}