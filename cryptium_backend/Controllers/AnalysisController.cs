using cryptium_backend.Models;
using cryptium_backend.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace cryptium_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AnalysisController : ControllerBase
    {
        private readonly CryptoService _cryptoService;
        private readonly AnalysisService _analysisService;

        public AnalysisController(
            CryptoService cryptoService,
            AnalysisService analysisService)
        {
            _cryptoService = cryptoService;
            _analysisService = analysisService;
        }

        [HttpPost]
        public IActionResult Analyze(
            [FromBody] AnalysisRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest("El texto no puede estar vacío.");

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest("La clave no puede estar vacía.");

            string encrypted =
                _cryptoService.Encrypt(
                    request.Text,
                    request.Key
                );

            byte[] encryptedBytes =
                Convert.FromBase64String(encrypted);

            double entropy =
                _analysisService.CalculateEntropy(
                    encryptedBytes
                );

            Dictionary<int, int> frequency =
                _analysisService.CalculateFrequency(
                    encryptedBytes
                );

            return Ok(new
            {
                encryptedText = encrypted,
                entropy,
                totalBytes = encryptedBytes.Length,
                uniqueBytes = frequency.Count,
                frequency
            });
        }

        [HttpPost("avalanche")]
        public IActionResult TestAvalanche(
            [FromBody] AnalysisRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest(new { message = "El texto de prueba no puede estar vacío." });

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest(new { message = "La clave experimental no puede estar vacía." });

            try
            {
                var result = _analysisService.AnalyzeAvalanche(
                    request.Text,
                    request.Key
                );

                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error en el cálculo del efecto avalancha: {ex.Message}" });
            }
        }

        [HttpPost("avalanche/batch")]
        public IActionResult TestAvalancheBatch(
            [FromBody] AvalancheBatchRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest(new { message = "El texto de prueba no puede estar vacío." });

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest(new { message = "La clave experimental no puede estar vacía." });

            try
            {
                var result = _analysisService.AnalyzeAvalancheBatch(request);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error en el análisis por lotes de avalancha: {ex.Message}" });
            }
        }

        [HttpPost("block-modes")]
        public IActionResult TestBlockModes(
            [FromBody] BlockPatternRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Text))
                return BadRequest(new { message = "El texto de prueba de bloques no puede estar vacío." });

            if (string.IsNullOrWhiteSpace(request.Key))
                return BadRequest(new { message = "La clave no puede estar vacía." });

            try
            {
                var result = _analysisService.AnalyzeBlockPatterns(
                    request.Text,
                    request.Key
                );

                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error en el análisis de modos de bloque: {ex.Message}" });
            }
        }

        [HttpPost("statistics")]
        public IActionResult TestCiphertextStatistics(
            [FromBody] CiphertextStatsRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.CiphertextBase64))
                return BadRequest(new { message = "El texto cifrado en Base64 no puede estar vacío." });

            try
            {
                var result = _analysisService.AnalyzeCiphertextStatistics(
                    request.CiphertextBase64,
                    request.HasIvPrefix
                );

                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Error al calcular las estadísticas del texto cifrado: {ex.Message}" });
            }
        }
    }
}