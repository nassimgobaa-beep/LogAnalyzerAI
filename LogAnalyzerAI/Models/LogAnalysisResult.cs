using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace LogAnalyzerAI.Models
{
    public class LogAnalysisResult
    {
        // backward-compatibility
        [JsonPropertyName("machine")]
        public string? Machine { get; set; }

        [JsonPropertyName("ip")]
        public List<string> Ip { get; set; } = new List<string>();

        [JsonPropertyName("errors")]
        public List<string> Errors { get; set; } = new List<string>();

        [JsonPropertyName("summary")]
        public string? Summary { get; set; }

        // New fields used by the UI / JS
        [JsonPropertyName("machineName")]
        public string? MachineName { get; set; }

        [JsonPropertyName("machineNames")]
        public List<string> MachineNames { get; set; } = new List<string>();

        [JsonPropertyName("ipAddresses")]
        public List<string> IpAddresses { get; set; } = new List<string>();

        [JsonPropertyName("networkIssues")]
        public List<string> NetworkIssues { get; set; } = new List<string>();

        [JsonPropertyName("timestamps")]
        public List<string> Timestamps { get; set; } = new List<string>();

        [JsonPropertyName("connections")]
        public List<ConnectionInfo> Connections { get; set; } = new List<ConnectionInfo>();
    }
}
