using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace LogAnalyzerAI.Models
{
    // Strict JSON schema required by the user:
    // { "machine": string, "ip": ["..."], "errors": ["..."], "summary": "..." }
    public class LogAnalysisResult
    {
        [JsonPropertyName("machine")]
        public string? Machine { get; set; }

        [JsonPropertyName("ip")]
        public List<string> Ip { get; set; } = new List<string>();

        [JsonPropertyName("errors")]
        public List<string> Errors { get; set; } = new List<string>();

        [JsonPropertyName("summary")]
        public string? Summary { get; set; }
    }
}
