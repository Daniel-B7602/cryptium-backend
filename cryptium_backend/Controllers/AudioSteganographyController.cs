using cryptium_backend.Models;
using cryptium_backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace cryptium_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [RequestSizeLimit(50 * 1024 * 1024)] // Límite de 50 MB por archivo
    public class AudioSteganographyController : ControllerBase
    {
        private readonly AudioSteganographyService _steganographyService;

        public AudioSteganographyController(AudioSteganographyService steganographyService)
        {
            _steganographyService = steganographyService;
        }

        [HttpPost("capacity")]
        public async Task<IActionResult> GetCapacity(
            IFormFile file,
            CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar un archivo de audio WAV." });
            }

            if (file.Length > 50 * 1024 * 1024)
            {
                return BadRequest(new { message = "El archivo supera el límite máximo permitido de 50 MB." });
            }

            try
            {
                using var ms = new MemoryStream();
                await file.CopyToAsync(ms, cancellationToken);
                byte[] audioBytes = ms.ToArray();

                var capacityInfo = _steganographyService.GetCapacity(audioBytes, file.FileName);
                return Ok(capacityInfo);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error inesperado al consultar la capacidad del audio: {ex.Message}" });
            }
        }

        [HttpPost("analyze")]
        public async Task<IActionResult> Analyze(
            IFormFile file,
            CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar un archivo de audio WAV para analizar." });
            }

            if (file.Length > 50 * 1024 * 1024)
            {
                return BadRequest(new { message = "El archivo supera el límite máximo permitido de 50 MB." });
            }

            try
            {
                using var ms = new MemoryStream();
                await file.CopyToAsync(ms, cancellationToken);
                byte[] audioBytes = ms.ToArray();

                var analysis = _steganographyService.AnalyzeAudio(audioBytes, file.FileName);
                return Ok(analysis);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error inesperado al analizar el archivo de audio: {ex.Message}" });
            }
        }

        [HttpPost("hide")]
        public async Task<IActionResult> Hide(
            IFormFile file,
            [FromForm] string message,
            [FromForm] string key,
            CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar un archivo de audio WAV portador." });
            }

            if (file.Length > 50 * 1024 * 1024)
            {
                return BadRequest(new { message = "El archivo supera el límite máximo permitido de 50 MB." });
            }

            if (string.IsNullOrEmpty(message))
            {
                return BadRequest(new { message = "Debes introducir el mensaje secreto a ocultar." });
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return BadRequest(new { message = "Debes introducir una contraseña criptográfica." });
            }

            try
            {
                using var ms = new MemoryStream();
                await file.CopyToAsync(ms, cancellationToken);
                byte[] audioBytes = ms.ToArray();

                byte[] stegoBytes = _steganographyService.HideMessage(audioBytes, message, key);

                string outputFileName = file.FileName.StartsWith("stego_", StringComparison.OrdinalIgnoreCase)
                    ? file.FileName
                    : $"stego_{file.FileName}";

                return File(
                    stegoBytes,
                    "audio/wav",
                    outputFileName
                );
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error al procesar el ocultamiento esteganográfico: {ex.Message}" });
            }
        }

        [HttpPost("extract")]
        public async Task<IActionResult> Extract(
            IFormFile file,
            [FromForm] string key,
            CancellationToken cancellationToken)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar un archivo de audio WAV." });
            }

            if (file.Length > 50 * 1024 * 1024)
            {
                return BadRequest(new { message = "El archivo supera el límite máximo permitido de 50 MB." });
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return BadRequest(new { message = "Debes introducir la contraseña para descifrar el mensaje." });
            }

            try
            {
                using var ms = new MemoryStream();
                await file.CopyToAsync(ms, cancellationToken);
                byte[] audioBytes = ms.ToArray();

                var result = _steganographyService.ExtractMessage(audioBytes, key, file.FileName);
                return Ok(result);
            }
            catch (UnauthorizedAccessException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error al extraer el mensaje del audio: {ex.Message}" });
            }
        }

        [HttpPost("compare")]
        public async Task<IActionResult> Compare(
            IFormFile originalFile,
            IFormFile stegoFile,
            CancellationToken cancellationToken)
        {
            if (originalFile == null || originalFile.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar el archivo de audio original." });
            }

            if (stegoFile == null || stegoFile.Length == 0)
            {
                return BadRequest(new { message = "Debes seleccionar el archivo de audio modificado (stego)." });
            }

            if (originalFile.Length > 50 * 1024 * 1024 || stegoFile.Length > 50 * 1024 * 1024)
            {
                return BadRequest(new { message = "Uno de los archivos supera el límite máximo permitido de 50 MB." });
            }

            try
            {
                using var msOrig = new MemoryStream();
                await originalFile.CopyToAsync(msOrig, cancellationToken);
                byte[] origBytes = msOrig.ToArray();

                using var msStego = new MemoryStream();
                await stegoFile.CopyToAsync(msStego, cancellationToken);
                byte[] stegoBytes = msStego.ToArray();

                var comparison = _steganographyService.CompareAudio(
                    origBytes,
                    originalFile.FileName,
                    stegoBytes,
                    stegoFile.FileName
                );

                return Ok(comparison);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"Error durante la comparación de audios: {ex.Message}" });
            }
        }
    }
}
