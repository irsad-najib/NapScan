/**
 * Tool Result Parsers
 * Centralized parsers for all scanning tools
 */

import { ScanVulnerability } from "@/context/ScanContext";
import { ToolKey } from "@/services/api";

// Re-export Nmap parser
export { parseNmapResults, parseNmapAuto, parseRawNmapScan } from "./nmapParser";
export type { ParsedNmapScanSummary, ParsedNmapHost, ParsedNmapPort } from "./nmapParser";

/**
 * Parse OWASP ZAP results
 */
export function parseZapResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        const alerts = rawResult?.alertsRaw || rawResult?.alerts || [];
        const alertArray = Array.isArray(alerts) ? alerts : [];

        alertArray.forEach((alert: any, idx: number) => {
            const risk = alert.risk?.toLowerCase() || alert.riskdesc?.toLowerCase() || "low";
            let severity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            if (risk.includes("high")) severity = "High";
            else if (risk.includes("medium")) severity = "Medium";
            else if (risk.includes("low")) severity = "Low";
            else if (risk.includes("informational")) severity = "Info";

            vulnerabilities.push({
                id: `zap-${idx}`,
                name: alert.alert || alert.name || "Unknown ZAP Finding",
                severity,
                description: alert.desc || alert.description || "No description available",
                tool: "zap",
            });
        });

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing ZAP results:", error);
        return [];
    }
}

/**
 * Parse OpenVAS results
 */
export function parseOpenVasResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        // OpenVAS typically returns XML, but if it's been converted to JSON
        const results = rawResult?.results || rawResult?.result || [];
        const resultArray = Array.isArray(results) ? results : [results];

        resultArray.forEach((result: any, idx: number) => {
            const threat = result.threat?.toLowerCase() || result.severity?.toLowerCase() || "log";
            let severity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            if (threat.includes("critical") || threat.includes("high")) severity = "High";
            else if (threat.includes("medium")) severity = "Medium";
            else if (threat.includes("low")) severity = "Low";

            vulnerabilities.push({
                id: `openvas-${idx}`,
                name: result.name || result.nvt?.name || "OpenVAS Finding",
                severity,
                description: result.description || "No description available",
                tool: "openvas",
            });
        });

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing OpenVAS results:", error);
        return [];
    }
}

/**
 * Parse Nuclei results
 */
export function parseNucleiResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        const results = rawResult?.results || [];
        const resultArray = Array.isArray(results) ? results : [];

        resultArray.forEach((result: any, idx: number) => {
            const severity = result.info?.severity?.toLowerCase() || "info";
            let vulnSeverity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            if (severity === "critical") vulnSeverity = "Critical";
            else if (severity === "high") vulnSeverity = "High";
            else if (severity === "medium") vulnSeverity = "Medium";
            else if (severity === "low") vulnSeverity = "Low";

            vulnerabilities.push({
                id: `nuclei-${idx}`,
                name: result.info?.name || result.templateID || "Nuclei Finding",
                severity: vulnSeverity,
                description: result.info?.description || result.matched || "No description available",
                tool: "nuclei",
            });
        });

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Nuclei results:", error);
        return [];
    }
}

/**
 * Parse SSLyze results
 */
export function parseSslyzeResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        const scanResults = rawResult?.server_scan_results || rawResult?.results || [];
        const resultArray = Array.isArray(scanResults) ? scanResults : [scanResults];

        resultArray.forEach((serverResult: any) => {
            const scanCommands = serverResult?.scan_commands_results || serverResult?.scan_result || {};

            // Check for SSL/TLS vulnerabilities
            if (scanCommands.heartbleed?.is_vulnerable_to_heartbleed) {
                vulnerabilities.push({
                    id: `sslyze-heartbleed`,
                    name: "Heartbleed Vulnerability Detected",
                    severity: "Critical",
                    description: "Server is vulnerable to the Heartbleed attack (CVE-2014-0160)",
                    tool: "sslyze",
                });
            }

            // Check for weak ciphers
            const cipherSuites = scanCommands.ssl_2_0_cipher_suites || scanCommands.ssl_3_0_cipher_suites;
            if (cipherSuites?.accepted_cipher_suites?.length > 0) {
                vulnerabilities.push({
                    id: `sslyze-weak-cipher`,
                    name: "Weak SSL/TLS Cipher Suites Detected",
                    severity: "High",
                    description: "Server supports weak or outdated cipher suites",
                    tool: "sslyze",
                });
            }

            // Check certificate validation
            const certInfo = scanCommands.certificate_info;
            if (certInfo?.certificate_deployments) {
                certInfo.certificate_deployments.forEach((deployment: any, idx: number) => {
                    if (deployment.leaf_certificate_is_ev === false) {
                        vulnerabilities.push({
                            id: `sslyze-cert-${idx}`,
                            name: "Certificate Validation Issue",
                            severity: "Medium",
                            description: "SSL certificate validation issues detected",
                            tool: "sslyze",
                        });
                    }
                });
            }
        });

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing SSLyze results:", error);
        return [];
    }
}

/**
 * Parse Ffuf results
 */
export function parseFfufResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        const results = rawResult?.results || [];
        const resultArray = Array.isArray(results) ? results : [];

        resultArray.forEach((result: any, idx: number) => {
            const status = result.status || result.statuscode || 0;
            let severity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            // Determine severity based on status code and content
            if (status >= 200 && status < 300) {
                severity = "Medium"; // Successful responses might expose sensitive paths
            } else if (status >= 300 && status < 400) {
                severity = "Low"; // Redirects
            } else if (status === 401 || status === 403) {
                severity = "Medium"; // Auth required but path exists
            }

            vulnerabilities.push({
                id: `ffuf-${idx}`,
                name: `Directory/File Found: ${result.url || result.input?.FUZZ || "Unknown"}`,
                severity,
                description: `HTTP ${status} - ${result.length || 0} bytes - ${result.words || 0} words`,
                tool: "ffuf",
            });
        });

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Ffuf results:", error);
        return [];
    }
}

/**
 * Main parser dispatcher - routes to appropriate parser based on tool
 */
export function parseToolResults(tool: ToolKey, rawResult: any): ScanVulnerability[] {
    try {
        switch (tool) {
            case "nmap":
                const { parseNmapAuto } = require("./nmapParser");
                return parseNmapAuto(rawResult);
            case "zap":
                return parseZapResults(rawResult);
            case "openvas":
                return parseOpenVasResults(rawResult);
            case "nuclei":
                return parseNucleiResults(rawResult);
            case "sslyze":
                return parseSslyzeResults(rawResult);
            case "ffuf":
                return parseFfufResults(rawResult);
            default:
                console.warn(`No parser available for tool: ${tool}`);
                return [];
        }
    } catch (error) {
        console.error(`Error parsing ${tool} results:`, error);
        return [];
    }
}
