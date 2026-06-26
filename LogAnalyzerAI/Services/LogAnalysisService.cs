using LogAnalyzerAI.Models;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

namespace LogAnalyzerAI.Services
{
    /// <summary>
    /// Implémentation du service d'analyse. Actuellement utilise un parseur local heuristique.
    /// Pour intégrer Microsoft.Extensions.AI, injecter et appeler IChatClient ici (voir TODO).
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

        private async Task<string?> CallOllamaAsync(string endpoint, string modelId, string logs, CancellationToken cancellationToken)
        {
            // Ollama local: POST {endpoint}/chat with { model: modelId, messages: [...] }
            var client = _httpClientFactory.CreateClient();
            var url = endpoint + "/chat";

            var prompt = "Tu es un expert en analyse de logs système et réseau.\n" +
                         "Analyse le contenu suivant et retourne un rapport structuré et exploitable en sections:\n" +
                         "1. Nom de la machine\n2. Adresse(s) IP détectée(s)\n3. Erreurs, exceptions, warnings\n4. Problèmes réseau potentiels (DNS, routeur, latence, serveur, PC)\n5. Résumé clair et actionnable\n\n" +
                         "Réponds en texte libre en précédant chaque section par son numéro. Si possible, renvoie aussi un JSON valide à la fin: { \"machineName\":..., \"ipAddresses\":[...], \"errors\":[...], \"networkIssues\":[...], \"summary\":... }\n\n" +
                         "Voici le contenu du log:\n" + logs;

            var request = new
            {
                model = modelId,
                messages = new[] { new { role = "user", content = prompt } }
            };

            var httpContent = new System.Net.Http.StringContent(System.Text.Json.JsonSerializer.Serialize(request));
            httpContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await client.PostAsync(url, httpContent, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var respText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            // Ollama returns a chat response string directly in many setups
            return respText;
        }

        public async Task<LogAnalysisResult> AnalyzeAsync(string concatenatedLogs, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(concatenatedLogs))
            {
                return new LogAnalysisResult { Summary = "Aucun contenu de log fourni." };
            }
            // Priorité: Ollama local (gratuit) si configuré via Ollama:Endpoint / OLLAMA_ENDPOINT
            var ollamaEndpoint = _configuration["Ollama:Endpoint"] ?? Environment.GetEnvironmentVariable("OLLAMA_ENDPOINT");
            var ollamaModel = _configuration["Ollama:ModelId"] ?? Environment.GetEnvironmentVariable("OLLAMA_MODEL") ?? "phi3";
            if (!string.IsNullOrWhiteSpace(ollamaEndpoint))
            {
                try
                {
                    var aiText = await CallOllamaAsync(ollamaEndpoint.TrimEnd('/'), ollamaModel, concatenatedLogs, cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(aiText))
                    {
                        var parsed = ParseAiResponse(aiText);
                        if (parsed != null) return parsed;
                        return new LogAnalysisResult { Summary = aiText };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erreur lors de l'appel Ollama, fallback utilisé.");
                }
            }

            // Vérifier ensuite OpenAI si configuré (env var OPENAI_API_KEY ou configuration OpenAI:ApiKey)
            var apiKey = _configuration["OpenAI:ApiKey"] ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY");
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                try
                {
                    var aiText = await CallOpenAiAsync(apiKey, concatenatedLogs, cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(aiText))
                    {
                        var parsed = ParseAiResponse(aiText);
                        if (parsed != null) return parsed;
                        return new LogAnalysisResult { Summary = aiText };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erreur lors de l'appel OpenAI, fallback local utilisé.");
                }
            }

            // Fallback: analyse locale simple
            return await Task.FromResult(SimpleLocalAnalysis(concatenatedLogs));
        }

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
                    if (result.MachineName == null) result.MachineName = name;
                    if (!result.MachineNames.Contains(name)) result.MachineNames.Add(name);
                }
            }

            // IPs
            var ipMatches = Regex.Matches(logs, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
            foreach (Match m in ipMatches)
            {
                if (!result.IpAddresses.Contains(m.Value)) result.IpAddresses.Add(m.Value);
            }

            // Timestamps
            var tsMatches = Regex.Matches(logs, @"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b");
            foreach (Match m in tsMatches)
            {
                if (!result.Timestamps.Contains(m.Value)) result.Timestamps.Add(m.Value);
            }

            // Errors
            var errorLines = Regex.Matches(logs, "(?im)^.*(?:Exception|ERROR|Error|WARN|Warning).*$");
            foreach (Match m in errorLines)
            {
                var line = m.Value.Trim();
                if (!result.Errors.Contains(line)) result.Errors.Add(line);
            }

            // Network issues heuristics
            var netLines = Regex.Matches(logs, "(?im)^.*(?:timeout|unreachable|packet loss|latency|DNS|router|routeur).*$");
            foreach (Match m in netLines)
            {
                var line = m.Value.Trim();
                if (!result.NetworkIssues.Contains(line)) result.NetworkIssues.Add(line);
            }

            result.Summary = $"Machines détectées: {(result.MachineName ?? "N/A")} - IPs: {string.Join(", ", result.IpAddresses)} - Erreurs: {result.Errors.Count} - Problèmes réseau détectés: {result.NetworkIssues.Count}";

            return result;
        }

        private async Task<string?> CallOpenAiAsync(string apiKey, string logs, CancellationToken cancellationToken)
        {
            // Appel REST minimal à l'API OpenAI pour le modèle gpt-4o-mini (assume endpoint api.openai.com)
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);

            var prompt = "Tu es un expert en analyse de logs système et réseau.\n" +
                         "Analyse le contenu suivant et retourne un rapport structuré et exploitable en sections:\n" +
                         "1. Nom de la machine\n2. Adresse(s) IP détectée(s)\n3. Erreurs, exceptions, warnings\n4. Problèmes réseau potentiels (DNS, routeur, latence, serveur, PC)\n5. Résumé clair et actionnable\n\n" +
                         "Réponds en texte libre en précédant chaque section par son numéro. Si possible, renvoie aussi un JSON valide à la fin: { \"machineName\":..., \"ipAddresses\":[...], \"errors\":[...], \"networkIssues\":[...], \"summary\":... }\n\n" +
                         "Voici le contenu du log:\n" + logs;

            var request = new
            {
                model = "gpt-4o-mini",
                messages = new[] { new { role = "user", content = prompt } },
                max_tokens = 1500,
                temperature = 0.0
            };

            var httpContent = new System.Net.Http.StringContent(System.Text.Json.JsonSerializer.Serialize(request));
            httpContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await client.PostAsync("https://api.openai.com/v1/chat/completions", httpContent, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var respText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            // Essayer d'extraire le texte de la réponse
            using var doc = System.Text.Json.JsonDocument.Parse(respText);
            if (doc.RootElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
            {
                var first = choices[0];
                if (first.TryGetProperty("message", out var message) && message.TryGetProperty("content", out var content))
                {
                    return content.GetString();
                }
                // Certains endpoints retournent "delta" fragments: essayer d'agréger
            }

            return respText;
        }

        private LogAnalysisResult? ParseAiResponse(string aiText)
        {
            if (string.IsNullOrWhiteSpace(aiText)) return null;

            var result = new LogAnalysisResult();

            try
            {
                // Essayer de trouver JSON final
                var jsonStart = aiText.IndexOf('{');
                if (jsonStart >= 0)
                {
                    var json = aiText.Substring(jsonStart);
                    try
                    {
                        var doc = System.Text.Json.JsonDocument.Parse(json);
                        var root = doc.RootElement;
                        if (root.TryGetProperty("machineName", out var machine)) result.MachineName = machine.GetString();
                        if (root.TryGetProperty("ipAddresses", out var ips) && ips.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var el in ips.EnumerateArray()) if (el.ValueKind == System.Text.Json.JsonValueKind.String)
                                    result.IpAddresses.Add(el.GetString()!);
                        }
                        if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var el in errors.EnumerateArray()) if (el.ValueKind == System.Text.Json.JsonValueKind.String)
                                    result.Errors.Add(el.GetString()!);
                        }
                        if (root.TryGetProperty("networkIssues", out var net) && net.ValueKind == System.Text.Json.JsonValueKind.Array)
                        {
                            foreach (var el in net.EnumerateArray()) if (el.ValueKind == System.Text.Json.JsonValueKind.String)
                                    result.NetworkIssues.Add(el.GetString()!);
                        }
                        if (root.TryGetProperty("summary", out var summary)) result.Summary = summary.GetString();

                        return result;
                    }
                    catch
                    {
                        // ignore parse error, continuer heuristique
                    }
                }

                // Heuristiques de parsing si pas de JSON
                var machineMatch = Regex.Match(aiText, "(?im)\\bNom de la machine\\b.*?:\\s*(.+)");
                if (machineMatch.Success) result.MachineName = machineMatch.Groups[1].Value.Trim();

                var ipMatches = Regex.Matches(aiText, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
                foreach (Match m in ipMatches) if (!result.IpAddresses.Contains(m.Value)) result.IpAddresses.Add(m.Value);

                var errorMatches = Regex.Matches(aiText, "(?im)^(.*(?:Exception|ERROR|Error|WARN|Warning).*)$", RegexOptions.Multiline);
                foreach (Match m in errorMatches)
                {
                    var line = m.Groups[1].Value.Trim();
                    if (!result.Errors.Contains(line)) result.Errors.Add(line);
                }

                var netMatches = Regex.Matches(aiText, "(?im)^(.*(?:DNS|routeur|latence|timeout|packet loss|latency|unreachable).*)$", RegexOptions.Multiline);
                foreach (Match m in netMatches)
                {
                    var line = m.Groups[1].Value.Trim();
                    if (!result.NetworkIssues.Contains(line)) result.NetworkIssues.Add(line);
                }

                // Summary -- take last 500 chars as summary fallback
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
