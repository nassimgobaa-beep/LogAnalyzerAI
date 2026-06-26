using LogAnalyzerAI.Models;

namespace LogAnalyzerAI.Services
{
    public interface ILogAnalysisService
    {
        /// <summary>
        /// Analyse le contenu des logs et retourne un résultat structuré.
        /// </summary>
        Task<LogAnalysisResult> AnalyzeAsync(string concatenatedLogs, CancellationToken cancellationToken = default);
    }
}