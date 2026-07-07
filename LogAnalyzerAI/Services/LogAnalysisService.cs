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

            if (string.IsNullOrWhiteSpace(logs))
            {
                result.Summary = "Aucun contenu de log fourni.";
                return result;
            }

            // timestamps (format dd/MM/yyyy HH:mm:ss)
            var tsMatches = Regex.Matches(logs, @"\b\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\b");
            foreach (Match m in tsMatches) if (!result.Timestamps.Contains(m.Value)) result.Timestamps.Add(m.Value);

            // hostnames (ex: vw069708.hosting.gfi) — capture noms avec au moins un point
            var hostnameMatches = Regex.Matches(logs, @"\b([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)\b");
            foreach (Match m in hostnameMatches)
            {
                var name = m.Groups[1].Value.Trim();

                // Exclure motifs clairement non-host (dates, times, numeric-only)
                if (Regex.IsMatch(name, @"^\d{1,2}/\d{1,2}/\d{2,4}$")) continue;
                if (name.Length < 4) continue;

                if (!result.MachineNames.Contains(name)) result.MachineNames.Add(name);
                if (!result.IpAddresses.Contains(name)) result.IpAddresses.Add(name); // also push to ipAddresses for UI
                if (!result.Ip.Contains(name)) result.Ip.Add(name); // legacy field
                if (string.IsNullOrEmpty(result.MachineName)) result.MachineName = name;
                if (string.IsNullOrEmpty(result.Machine)) result.Machine = name;
            }

            // IPs (v4)
            var ipMatches = Regex.Matches(logs, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");
            foreach (Match m in ipMatches)
            {
                var ip = m.Value;
                if (!result.IpAddresses.Contains(ip)) result.IpAddresses.Add(ip);
                if (!result.Ip.Contains(ip)) result.Ip.Add(ip);
            }

            // Erreurs et problèmes réseau
            var errorLines = Regex.Matches(logs, "(?im)^.*(?:Exception|ERROR|Error|WARN|Warning|timeout|failed|refused|denied).*$");
            foreach (Match m in errorLines)
            {
                var line = m.Value.Trim();
                if (!result.Errors.Contains(line)) result.Errors.Add(line);
                if (!result.NetworkIssues.Contains(line)) result.NetworkIssues.Add(line);
            }

            // Détection heuristique de liaisons / connexions à partir de motifs courants
            var connPatterns = new[]
            {
                // from X to Y
                new { Pattern = @"\bfrom\s+([^\s,:;]+)\s+to\s+([^\s,:;]+)", Options = RegexOptions.IgnoreCase },
                // connected to X[:port]
                new { Pattern = @"\bconnected to\s+([^\s,:;]+)(?::(\d+))?", Options = RegexOptions.IgnoreCase },
                // accepted connection from X
                new { Pattern = @"\baccepted connection from\s+([^\s,:;]+)(?::(\d+))?", Options = RegexOptions.IgnoreCase },
                // established connection to X[:port]
                new { Pattern = @"\bestablished (?:tcp|udp)?\s*connection to\s+([^\s,:;]+)(?::(\d+))?", Options = RegexOptions.IgnoreCase },
                // arrow style -> target
                new { Pattern = @"\b->\s*([^\s,;]+)", Options = RegexOptions.None }
            };

            foreach (var p in connPatterns)
            {
                var matches = Regex.Matches(logs, p.Pattern, p.Options);
                foreach (Match m in matches)
                {
                    try
                    {
                        if (m.Groups.Count >= 3 && !string.IsNullOrEmpty(m.Groups[2].Value))
                        {
                            // patterns with two groups (from X to Y) or with optional port captured
                            if (p.Pattern.StartsWith(@"\bfrom"))
                            {
                                var src = m.Groups[1].Value.Trim();
                                var tgt = m.Groups[2].Value.Trim();
                                var c = new Models.ConnectionInfo { Source = src, Target = tgt, Line = m.Value.Trim() };
                                result.Connections.Add(c);
                            }
                            else
                            {
                                var target = m.Groups[1].Value.Trim();
                                int? port = null;
                                if (int.TryParse(m.Groups[2].Value, out var pval)) port = pval;
                                var c2 = new Models.ConnectionInfo { Target = target, Port = port, Line = m.Value.Trim() };
                                result.Connections.Add(c2);
                            }
                        }
                        else if (m.Groups.Count >= 2)
                        {
                            var g1 = m.Groups[1].Value.Trim();
                            var c3 = new Models.ConnectionInfo { Target = g1, Line = m.Value.Trim() };
                            result.Connections.Add(c3);
                        }
                    }
                    catch
                    {
                        // ignoré — heuristique non critique
                    }
                }
            }

            // Enrichissement: si pas de connections détectées, message explicite
            if (result.Connections.Count == 0)
            {
                result.Summary = "Aucune liaison réseau explicite détectée dans les logs fournis.";
            }
            else
            {
                result.Summary = $"Liaisons détectées: {result.Connections.Count} - IPs: {string.Join(", ", result.IpAddresses)} - Erreurs: {result.Errors.Count}";
            }

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
