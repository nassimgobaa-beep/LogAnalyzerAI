using LogAnalyzerAI.Models;
using LogAnalyzerAI.Services;
using Microsoft.AspNetCore.Mvc;

namespace LogAnalyzerAI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LogAnalyzerController : ControllerBase
    {
        private readonly ILogAnalysisService _service;
        private readonly ILogger<LogAnalyzerController> _logger;

        public LogAnalyzerController(ILogAnalysisService service, ILogger<LogAnalyzerController> logger)
        {
            _service = service;
            _logger = logger;
        }

        [HttpPost("analyze")]
        public async Task<IActionResult> AnalyzeLogs([FromForm] List<IFormFile> files)
        {
            if (files == null || files.Count == 0)
            {
                return BadRequest(new { error = "Aucun fichier envoyé." });
            }

            try
            {
                var combined = new System.Text.StringBuilder();

                foreach (var file in files)
                {
                    using var stream = file.OpenReadStream();
                    using var reader = new System.IO.StreamReader(stream);
                    var content = await reader.ReadToEndAsync();
                    combined.AppendLine($"--- Start File: {file.FileName} ---");
                    combined.AppendLine(content);
                    combined.AppendLine($"--- End File: {file.FileName} ---\n");
                }

                var analysis = await _service.AnalyzeAsync(combined.ToString());
                return Ok(analysis);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur pendant l'analyse des logs");
                return StatusCode(500, new { error = "Erreur serveur lors de l'analyse." });
            }
        }
    }
}