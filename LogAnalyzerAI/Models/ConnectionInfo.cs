using System.Text.Json.Serialization;

namespace LogAnalyzerAI.Models
{
    public class ConnectionInfo
    {
        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("target")]
        public string? Target { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("port")]
        public int? Port { get; set; }

        [JsonPropertyName("line")]
        public string? Line { get; set; }
    }
}