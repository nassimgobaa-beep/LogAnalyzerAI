using System.Collections.Generic;

namespace LogAnalyzerAI.Models
{
    public class LogAnalysisResult
    {
        // Premier nom de machine détecté (conforme à la demande)
        public string? MachineName { get; set; }

        // Liste des noms de machines détectés (fonctionnalité supplémentaire)
        public List<string> MachineNames { get; set; } = new List<string>();

        public List<string> IpAddresses { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();
        public List<string> NetworkIssues { get; set; } = new List<string>();

        // Timestamps détectés dans les logs (fonctionnalité supplémentaire)
        public List<string> Timestamps { get; set; } = new List<string>();

        public string? Summary { get; set; }
    }
}