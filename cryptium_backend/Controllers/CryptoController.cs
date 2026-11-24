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
                return BadRequest(new { message = "El texto no puede estar vacío." });

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest(new { message = "Debes proporcionar una clave válida." });

            try
            {
                var response = _cryptoService.EncryptText(
                    request.Text,
                    request.Key,
                    request.Algorithm ?? "AES"
                );

                return Ok(response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error durante el cifrado: {ex.Message}" });
            }
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt([FromBody] CryptoRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest(new { message = "El texto cifrado no puede estar vacío." });

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest(new { message = "Debes proporcionar una clave válida." });

            try
            {
                var response = _cryptoService.DecryptText(
                    request.Text,
                    request.Key,
                    request.Algorithm ?? "AES"
                );

                return Ok(response);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error durante el descifrado: {ex.Message}" });
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
