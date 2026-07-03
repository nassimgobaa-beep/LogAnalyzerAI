using LogAnalyzerAI.Models;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace LogAnalyzerAI.Services
{
    /// <summary>
    /// Implementation of the analysis service using OpenAI via the referenced OpenAI.dll ChatClient when available.
    /// Ollama-related code has been removed.
    /// The service will try to use the ChatClient.CompleteChatAsync with a JSON schema response format,
    /// and fallback to a direct REST call if the ChatClient cannot be invoked via reflection.
    /// </summary>
    public class LogAnalysisService : ILogAnalysisService
    {
        private readonly ILogger<LogAnalysisService> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        public LogAnalysisService(ILogger<LogAnalysisService> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        public async Task<LogAnalysisResult> AnalyzeAsync(string concatenatedLogs, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(concatenatedLogs))
            {
                return new LogAnalysisResult { Summary = "Aucun contenu de log fourni." };
            }

            var prompt = BuildPrompt(concatenatedLogs);

            // Use OpenAI REST directly if API key present
            var apiKey = _configuration["OpenAI:ApiKey"] ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY");
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                try
                {
                    var aiText = await CallOpenAiRestAsync(apiKey, prompt, cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(aiText))
                    {
                        var parsed = ParseAiResponse(aiText);
                        if (parsed != null) return parsed;
                        return new LogAnalysisResult { Summary = aiText };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erreur lors de l'appel REST OpenAI, fallback local utilisé.");
                }
            }

            // Last fallback: simple local analysis
            return await Task.FromResult(SimpleLocalAnalysis(concatenatedLogs));
        }

        private string BuildPrompt(string logs)
        {
            return "You are an expert in system and network log analysis.\n" +
                   "Return a strict JSON object ONLY (no extra text) with the following fields: \n" +
                   "- machine: string (the machine name)\n" +
                   "- ip: array of strings (detected IP addresses)\n" +
                   "- errors: array of strings (error lines)\n" +
                   "- summary: string (concise, actionable summary)\n\n" +
                   "Here are the logs to analyze:\n" + logs;
        }

        // REST-only implementation: TryCallChatClientAsync removed for a simpler, maintainable REST approach.

        private LogAnalysisResult SimpleLocalAnalysis(string logs)
        {
            var result = new LogAnalysisResult();

            // Machine names: heuristique
            var machineMatches = Regex.Matches(logs, @"\b(hostname|machine|server)[:=]\s*([\w\-\.]+)", RegexOptions.IgnoreCase);
            foreach (Match m in machineMatches)
            {
                var name = m.Groups[2].Value.Trim();
                if (!string.IsNullOrEmpty(name))
                {
                    if (string.IsNullOrEmpty(result.Machine)) result.Machine = name;
                    if (!result.Ip.Contains(name)) result.Ip.Add(name);
                }
            }

            // IPs
            var ipMatches = Regex.Matches(logs, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
            foreach (Match m in ipMatches)
            {
                if (!result.Ip.Contains(m.Value)) result.Ip.Add(m.Value);
            }

            // Errors
            var errorLines = Regex.Matches(logs, "(?im)^.*(?:Exception|ERROR|Error|WARN|Warning).*$");
            foreach (Match m in errorLines)
            {
                var line = m.Value.Trim();
                if (!result.Errors.Contains(line)) result.Errors.Add(line);
            }

            result.Summary = $"Machines détectées: {(result.Machine ?? "N/A")} - IPs: {string.Join(", ", result.Ip)} - Erreurs: {result.Errors.Count}";

            return result;
        }

        private async Task<string?> CallOpenAiRestAsync(string apiKey, string prompt, CancellationToken cancellationToken)
        {
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);

            var request = new
            {
                model = "gpt-4o-mini",
                messages = new[] { new { role = "user", content = prompt } },
                max_tokens = 1500,
                temperature = 0.0
            };

            var httpContent = new System.Net.Http.StringContent(JsonSerializer.Serialize(request));
            httpContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            // Read endpoint from configuration / env var, fallback to current default
            var endpoint = _configuration["OpenAI:Endpoint"]
                           ?? Environment.GetEnvironmentVariable("OPENAI_API_ENDPOINT")
                           ?? "https://api.openai.com/v1/chat/completions";

            var response = await client.PostAsync(endpoint, httpContent, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var respText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            // Try to extract textual content
            try
            {
                using var doc = JsonDocument.Parse(respText);
                if (doc.RootElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
                {
                    var first = choices[0];
                    if (first.TryGetProperty("message", out var message) && message.TryGetProperty("content", out var content))
                    {
                        return content.GetString();
                    }
                }
            }
            catch { }

            return respText;
        }

        private LogAnalysisResult? ParseAiResponse(string aiText)
        {
            if (string.IsNullOrWhiteSpace(aiText)) return null;

            try
            {
                // Try to parse direct JSON
                var jsonStart = aiText.IndexOf('{');
                if (jsonStart >= 0)
                {
                    var json = aiText.Substring(jsonStart);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var parsed = JsonSerializer.Deserialize<LogAnalysisResult>(json, options);
                    if (parsed != null) return parsed;
                }

                // Fallback heuristics
                var result = new LogAnalysisResult();
                var ipMatches = Regex.Matches(aiText, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
                foreach (Match m in ipMatches) if (!result.Ip.Contains(m.Value)) result.Ip.Add(m.Value);

                var errorMatches = Regex.Matches(aiText, "(?im)^(.*(?:Exception|ERROR|Error|WARN|Warning).*)$", RegexOptions.Multiline);
                foreach (Match m in errorMatches)
                {
                    var line = m.Groups[1].Value.Trim();
                    if (!result.Errors.Contains(line)) result.Errors.Add(line);
                }

                result.Summary = aiText.Length > 500 ? aiText.Substring(0, 500) : aiText;
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erreur lors du parsing IA");
                return null;
            }
        }
    }
}
