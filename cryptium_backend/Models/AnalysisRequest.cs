namespace cryptium_backend.Models
{
    public class AnalysisRequest
    {
        public string Text { get; set; } = string.Empty;

        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// Índice del byte a modificar en la prueba de avalancha (por defecto 0).
        /// </summary>
        public int? ByteIndex { get; set; }

        /// <summary>
        /// Índice del bit a invertir (0 a 7, donde 0 es LSB). Por defecto 0.
        /// </summary>
        public int? BitIndex { get; set; }
    }
}
