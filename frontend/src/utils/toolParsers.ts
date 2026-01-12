/**
 * Tool Result Parsers
 * Centralized parsers for all scanning tools
 */

import { ScanVulnerability } from "@/context/ScanContext";
import { ToolKey } from "@/services/api";

// Re-export Nmap parser
export { parseNmapResults, parseNmapAuto, parseRawNmapScan } from "./nmapParser";
export type { ParsedNmapScanSummary, ParsedNmapHost, ParsedNmapPort } from "./nmapParser";

// Re-export ZAP parser
export { parseZapResults, parseZapAuto, parseZapResultsDetailed, analyzeZapRisk } from "./zapParser";
export type { ParsedZapVulnerability, ZapRiskSummary, ZapAlert } from "./zapParser";

// Note: parseZapResults is now exported from ./zapParser

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
 * Parse Nuclei results - handles various response formats
 */
export function parseNucleiResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        console.log("[Nuclei Parser] Raw result type:", typeof rawResult);
        console.log("[Nuclei Parser] Raw result:", rawResult);

        let results: any[] = [];

        // Handle different possible structures
        if (Array.isArray(rawResult)) {
            // Direct array of results
            results = rawResult;
        } else if (Array.isArray(rawResult?.results)) {
            // Results in 'results' field
            results = rawResult.results;
        } else if (typeof rawResult === "string") {
            // NDJSON format (newline-delimited JSON)
            try {
                results = rawResult.split("\n").filter(line => line.trim()).map(line => JSON.parse(line));
            } catch {
                console.log("[Nuclei Parser] Failed to parse as NDJSON");
            }
        } else if (rawResult?.output && typeof rawResult.output === "string") {
            // Output field with NDJSON
            try {
                results = rawResult.output.split("\n").filter((line: string) => line.trim()).map((line: string) => JSON.parse(line));
            } catch {
                console.log("[Nuclei Parser] Failed to parse output as NDJSON");
            }
        }

        console.log("[Nuclei Parser] Found", results.length, "results to parse");

        results.forEach((result: any, idx: number) => {
            const severity = (result.info?.severity || result.severity || "info").toLowerCase();
            let vulnSeverity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            if (severity === "critical") vulnSeverity = "Critical";
            else if (severity === "high") vulnSeverity = "High";
            else if (severity === "medium") vulnSeverity = "Medium";
            else if (severity === "low") vulnSeverity = "Low";

            const name = result.info?.name || result["template-id"] || result.templateID || result.template || "Nuclei Finding";
            const description = result.info?.description || result.matcher_name || result.matched || result.host || "No description available";

            vulnerabilities.push({
                id: `nuclei-${idx}`,
                name: name,
                severity: vulnSeverity,
                description: description,
                tool: "nuclei",
            });
        });

        console.log("[Nuclei Parser] Parsed", vulnerabilities.length, "vulnerabilities");
        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Nuclei results:", error);
        return [];
    }
}

/**
 * Parse SSLyze results - handles CLI text output format
 */
export function parseSslyzeResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = 0;

    try {
        // Extract text output from the raw result
        let textOutput = "";

        // Handle different possible structures
        if (typeof rawResult === "string") {
            textOutput = rawResult;
        } else if (typeof rawResult?.error === "string") {
            textOutput = rawResult.error;
        } else if (typeof rawResult?.output === "string") {
            textOutput = rawResult.output;
        } else if (typeof rawResult?.message === "string") {
            textOutput = rawResult.message;
        }

        console.log("[SSLyze Parser] Raw result type:", typeof rawResult);
        console.log("[SSLyze Parser] Text output length:", textOutput.length);
        console.log("[SSLyze Parser] Contains SCAN RESULTS:", textOutput.includes("SCAN RESULTS FOR"));

        // If no text output found, return empty
        if (!textOutput || textOutput.length < 100) {
            console.log("[SSLyze Parser] No valid text output found");
            return vulnerabilities;
        }

        // Check for TLS 1.0 support
        if (textOutput.includes("TLS 1.0 Cipher Suites") &&
            textOutput.includes("The server accepted the following") &&
            textOutput.match(/\* TLS 1\.0 Cipher Suites:[\s\S]*?The server accepted the following \d+ cipher suites/)) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Deprecated TLS 1.0 Supported",
                severity: "Medium",
                description: "Server supports TLS 1.0 which is deprecated. Consider disabling for better security.",
                tool: "sslyze",
            });
        }

        // Check for TLS 1.1 support
        if (textOutput.includes("TLS 1.1 Cipher Suites") &&
            textOutput.includes("The server accepted the following") &&
            textOutput.match(/\* TLS 1\.1 Cipher Suites:[\s\S]*?The server accepted the following \d+ cipher suites/)) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Deprecated TLS 1.1 Supported",
                severity: "Medium",
                description: "Server supports TLS 1.1 which is deprecated. Consider disabling for better security.",
                tool: "sslyze",
            });
        }

        // Check for SSL 2.0/3.0 (critical)
        if (textOutput.includes("SSL 2.0") && !textOutput.match(/SSL 2\.0[\s\S]*?rejected all cipher suites/)) {
            const ssl2Match = textOutput.match(/\* SSL 2\.0 Cipher Suites:[\s\S]*?(rejected all|accepted the following)/);
            if (ssl2Match && ssl2Match[1].includes("accepted")) {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Critical: SSL 2.0 Supported",
                    severity: "Critical",
                    description: "Server supports SSL 2.0 which has major security vulnerabilities. Disable immediately!",
                    tool: "sslyze",
                });
            }
        }

        // Check for 3DES cipher
        if (textOutput.includes("TLS_RSA_WITH_3DES_EDE_CBC_SHA")) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Weak Cipher: 3DES Supported",
                severity: "High",
                description: "Server supports 3DES cipher suite which is considered weak.",
                tool: "sslyze",
            });
        }

        // Check for compliance failures
        if (textOutput.includes("FAILED - Not compliant")) {
            // Extract tls_versions issue
            const tlsVersionsMatch = textOutput.match(/\* tls_versions:([^\n]+)/);
            if (tlsVersionsMatch) {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Compliance: TLS Versions",
                    severity: "Medium",
                    description: tlsVersionsMatch[1].trim(),
                    tool: "sslyze",
                });
            }

            // Extract ciphers issue
            const ciphersMatch = textOutput.match(/\* ciphers:([^\n]+)/);
            if (ciphersMatch) {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Compliance: Cipher Suites",
                    severity: "Medium",
                    description: "Non-compliant cipher suites are supported (see raw output for details)",
                    tool: "sslyze",
                });
            }

            // Extract curves issue
            const curvesMatch = textOutput.match(/\* tls_curves:([^\n]+)/);
            if (curvesMatch) {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Compliance: TLS Curves",
                    severity: "Low",
                    description: curvesMatch[1].trim(),
                    tool: "sslyze",
                });
            }
        }

        // Check for Heartbleed
        if (textOutput.includes("Heartbleed") && textOutput.toLowerCase().includes("vulnerable")) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Heartbleed Vulnerability",
                severity: "Critical",
                description: "Server is vulnerable to the Heartbleed attack (CVE-2014-0160)",
                tool: "sslyze",
            });
        }

        // Check for ROBOT attack
        if (textOutput.includes("ROBOT") && textOutput.toLowerCase().includes("vulnerable")) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "ROBOT Attack Vulnerability",
                severity: "Critical",
                description: "Server is vulnerable to the ROBOT attack",
                tool: "sslyze",
            });
        }

        // Check Certificate Transparency warning
        if (textOutput.includes("Certificate Transparency") && textOutput.includes("WARNING")) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Certificate Transparency Warning",
                severity: "Low",
                description: "Certificate has fewer SCTs than recommended by Google",
                tool: "sslyze",
            });
        }

        console.log(`[SSLyze Parser] Found ${vulnerabilities.length} vulnerabilities`);
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
                const { parseZapAuto } = require("./zapParser");
                return parseZapAuto(rawResult);
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
