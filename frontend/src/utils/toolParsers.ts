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
 * Parse Nuclei results - handles various response formats including compact summary format
 */
export function parseNucleiResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        console.log("[Nuclei Parser] Raw result type:", typeof rawResult);
        console.log("[Nuclei Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        let results: any[] = [];

        // Handle different possible structures
        // Format 1: Compact summary format { summary: { findings: [...] } }
        if (rawResult?.summary?.findings && Array.isArray(rawResult.summary.findings)) {
            console.log("[Nuclei Parser] Found compact summary format with", rawResult.summary.findings.length, "findings");
            results = rawResult.summary.findings;
        }
        // Format 2: Direct array of results
        else if (Array.isArray(rawResult)) {
            results = rawResult;
        }
        // Format 3: data wrapper { data: { results: [...] } } or { data: { summary: { findings: [...] } } }
        else if (rawResult?.data) {
            if (rawResult.data.summary?.findings && Array.isArray(rawResult.data.summary.findings)) {
                results = rawResult.data.summary.findings;
            } else if (Array.isArray(rawResult.data.results)) {
                results = rawResult.data.results;
            } else if (Array.isArray(rawResult.data)) {
                results = rawResult.data;
            }
        }
        // Format 4: Results in 'results' field (async format)
        else if (Array.isArray(rawResult?.results)) {
            results = rawResult.results;
        }
        // Format 5: NDJSON string format
        else if (typeof rawResult === "string") {
            try {
                results = rawResult.split("\n").filter(line => line.trim()).map(line => JSON.parse(line));
            } catch {
                console.log("[Nuclei Parser] Failed to parse as NDJSON");
            }
        }
        // Format 6: Output field with NDJSON
        else if (rawResult?.output && typeof rawResult.output === "string") {
            try {
                results = rawResult.output.split("\n").filter((line: string) => line.trim()).map((line: string) => JSON.parse(line));
            } catch {
                console.log("[Nuclei Parser] Failed to parse output as NDJSON");
            }
        }

        console.log("[Nuclei Parser] Found", results.length, "results to parse");

        // Track unique findings to avoid duplicates (by template_id + matched_at)
        const seenFindings = new Set<string>();

        results.forEach((result: any, idx: number) => {
            // Handle both compact format and full format
            const severity = (result.severity || result.info?.severity || "info").toLowerCase();
            let vulnSeverity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            if (severity === "critical") vulnSeverity = "Critical";
            else if (severity === "high") vulnSeverity = "High";
            else if (severity === "medium") vulnSeverity = "Medium";
            else if (severity === "low") vulnSeverity = "Low";

            // Handle compact format fields
            const name = result.name || result.info?.name || result["template-id"] || result.templateID || result.template || "Nuclei Finding";
            const matchedAt = result.matched_at || result["matched-at"] || result.host || result.url || "";
            const templateId = result.template_id || result["template-id"] || result.templateID || "";
            const tags = result.tags || result.info?.tags || [];

            // Create unique key for deduplication
            const uniqueKey = `${templateId}:${matchedAt}`;
            if (seenFindings.has(uniqueKey)) {
                return; // Skip duplicate
            }
            seenFindings.add(uniqueKey);

            // For compact format, description is not available
            const description = result.info?.description ||
                (tags.length > 0 ? `Tags: ${tags.join(", ")}` : `Template: ${templateId}`);

            const matcherName = result["matcher-name"] || result.matcher_name || "";
            const references = result.info?.reference || [];
            const remediation = result.info?.remediation || "";
            const cweId = result.info?.classification?.["cwe-id"] || [];
            const cveId = result.info?.classification?.["cve-id"] || null;

            vulnerabilities.push({
                id: `nuclei-${idx}`,
                name: name,
                severity: vulnSeverity,
                description: description,
                tool: "nuclei",
                // Store additional data for display
                affectedAsset: matchedAt,
                recommendation: remediation,
                cweId: Array.isArray(cweId) ? cweId.join(", ") : cweId,
                cveId: cveId,
                references: Array.isArray(references) ? references : [references],
                tags: Array.isArray(tags) ? tags : [],
                templateId: templateId,
                matcherName: matcherName,
            });
        });

        console.log("[Nuclei Parser] Parsed", vulnerabilities.length, "unique vulnerabilities");
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
 * Parse Ffuf results - handles various response formats
 */
export function parseFfufResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        console.log("[FFUF Parser] Raw result type:", typeof rawResult);
        console.log("[FFUF Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        // Handle different possible structures
        // Structure 1: { data: { results: [...] } } (API response)
        // Structure 2: { results: [...] } (direct)
        // Structure 3: Direct array
        let results: any[] = [];

        if (Array.isArray(rawResult)) {
            results = rawResult;
        } else if (rawResult?.data?.results && Array.isArray(rawResult.data.results)) {
            results = rawResult.data.results;
        } else if (rawResult?.results && Array.isArray(rawResult.results)) {
            results = rawResult.results;
        }

        console.log("[FFUF Parser] Found", results.length, "results to parse");

        results.forEach((result: any, idx: number) => {
            const status = result.status || result.statuscode || 0;
            const path = result.input?.FUZZ || result.url || "";
            const url = result.url || "";
            const length = result.length || 0;
            const words = result.words || 0;
            const lines = result.lines || 0;
            const duration = result.duration || 0;
            const redirectLocation = result.redirectlocation || "";

            let severity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";
            let category = "Discovered Path";

            // Critical: Sensitive files
            if (/\.env($|\.)/i.test(path)) {
                severity = "Critical";
                category = "Environment File";
            } else if (/\.git(\/|$)/i.test(path)) {
                severity = "Critical";
                category = "Git Repository";
            } else if (/backup.*\.(sql|zip|tar|gz)$|dump\.sql$|db\.sql$|database\.sql$/i.test(path)) {
                severity = "Critical";
                category = "Backup/Database";
            } else if (/\.htaccess$|\.htpasswd$/i.test(path)) {
                severity = "Critical";
                category = "Server Config";
            } else if (/wp-config\.php|config\.php$/i.test(path)) {
                severity = "Critical";
                category = "Config File";
            }
            // High: Admin & Config
            else if (/admin|administrator|manager/i.test(path)) {
                severity = "High";
                category = "Admin Panel";
            } else if (/swagger|openapi|api-docs/i.test(path)) {
                severity = "High";
                category = "API Documentation";
            } else if (/config\.(json|yml|yaml|xml)$/i.test(path)) {
                severity = "High";
                category = "Configuration";
            } else if (/composer|package.*\.json|docker|Dockerfile/i.test(path)) {
                severity = "High";
                category = "Build/Deploy Config";
            } else if (/phpinfo|server-status|server-info/i.test(path)) {
                severity = "High";
                category = "Server Info";
            }
            // Medium: Debug & Test & API
            else if (/debug|\.log$|error_log/i.test(path)) {
                severity = "Medium";
                category = "Debug/Logs";
            } else if (/test(s)?$|staging|dev$|\.dev\./i.test(path)) {
                severity = "Medium";
                category = "Test/Dev Endpoint";
            } else if (/api\/?$|\/v[0-9]+\/?$/i.test(path)) {
                severity = "Medium";
                category = "API Endpoint";
            } else if (/upload|uploads|files|media/i.test(path)) {
                severity = "Medium";
                category = "File Upload";
            }
            // Low: Common paths
            else if (/login|signin|auth|register|signup/i.test(path)) {
                severity = "Low";
                category = "Authentication";
            } else if (/static|assets|css|js|images|fonts/i.test(path)) {
                severity = "Info";
                category = "Static Resources";
            } else if (/dashboard|profile|settings|account/i.test(path)) {
                severity = "Low";
                category = "User Pages";
            }
            // Adjust severity based on status code
            else if (status >= 200 && status < 300) {
                severity = "Medium"; // Successful responses might expose something
            } else if (status === 401 || status === 403) {
                severity = "Low"; // Auth required but path exists
            } else if (status >= 300 && status < 400) {
                severity = "Info"; // Redirects
            }

            const name = severity === "Info"
                ? `Path Found: /${path}`
                : `${category}: /${path}`;

            vulnerabilities.push({
                id: `ffuf-${idx}`,
                name: name,
                severity,
                description: `HTTP ${status} | Size: ${length}B | Words: ${words} | Lines: ${lines}${redirectLocation ? ` | Redirect: ${redirectLocation}` : ""}`,
                tool: "ffuf",
                affectedAsset: url,
            });
        });

        console.log("[FFUF Parser] Parsed", vulnerabilities.length, "vulnerabilities");
        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Ffuf results:", error);
        return [];
    }
}

/**
 * Parse MobSF scan results - handles both summary.findings and report.android_api formats
 */
export function parseMobsfResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = 0;

    try {
        console.log("[MobSF Parser] Parsing results...");
        console.log("[MobSF Parser] Raw result keys:", Object.keys(rawResult || {}));

        // Handle nested data structure
        const data = rawResult?.data || rawResult;

        // Map MobSF severity to our severity type
        const mapSeverity = (mobsfSeverity: string): "Critical" | "High" | "Medium" | "Low" | "Info" => {
            const sev = (mobsfSeverity || "info").toLowerCase();
            if (sev === "critical" || sev === "danger") return "Critical";
            if (sev === "high") return "High";
            if (sev === "warning" || sev === "medium") return "Medium";
            if (sev === "low") return "Low";
            return "Info";
        };

        // --- Format 1: report.android_api structure ---
        const report = data?.report;
        if (report) {
            console.log("[MobSF Parser] Found report object, parsing android_api...");

            // Parse android_api findings
            const androidApi = report?.android_api;
            if (androidApi && typeof androidApi === "object") {
                Object.entries(androidApi).forEach(([apiName, apiData]: [string, any]) => {
                    const metadata = apiData?.metadata;
                    if (metadata) {
                        vulnerabilities.push({
                            id: `mobsf-${vulnIdx++}`,
                            name: apiName.replace(/_/g, ' ').replace(/api /i, ''),
                            severity: mapSeverity(metadata.severity),
                            description: metadata.description || apiName,
                            tool: "mobsf",
                        });
                    }
                });
            }

            // Parse code_analysis findings
            const codeAnalysis = report?.code_analysis;
            if (codeAnalysis && typeof codeAnalysis === "object") {
                Object.entries(codeAnalysis).forEach(([ruleName, ruleData]: [string, any]) => {
                    const metadata = ruleData?.metadata;
                    if (metadata) {
                        vulnerabilities.push({
                            id: `mobsf-${vulnIdx++}`,
                            name: metadata.description || ruleName,
                            severity: mapSeverity(metadata.severity),
                            description: `${metadata.description}${ruleData.files ? ` (${Object.keys(ruleData.files).length} files affected)` : ''}`,
                            tool: "mobsf",
                        });
                    }
                });
            }

            // Parse manifest_analysis findings
            const manifestAnalysis = report?.manifest_analysis;
            if (Array.isArray(manifestAnalysis)) {
                manifestAnalysis.forEach((finding: any) => {
                    vulnerabilities.push({
                        id: `mobsf-${vulnIdx++}`,
                        name: finding.title?.replace(/<[^>]*>/g, '') || "Manifest Issue",
                        severity: mapSeverity(finding.severity),
                        description: finding.description || "No description",
                        tool: "mobsf",
                    });
                });
            }

            // Parse certificate_analysis
            const certAnalysis = report?.certificate_analysis;
            if (certAnalysis?.certificate_findings && Array.isArray(certAnalysis.certificate_findings)) {
                certAnalysis.certificate_findings.forEach((finding: any) => {
                    vulnerabilities.push({
                        id: `mobsf-${vulnIdx++}`,
                        name: finding.title || "Certificate Issue",
                        severity: mapSeverity(finding.severity),
                        description: finding.description || "No description",
                        tool: "mobsf",
                    });
                });
            }

            // Parse permissions
            const permissions = report?.permissions;
            if (permissions && typeof permissions === "object") {
                Object.entries(permissions).forEach(([permName, permData]: [string, any]) => {
                    if (permData?.status === "dangerous") {
                        vulnerabilities.push({
                            id: `mobsf-${vulnIdx++}`,
                            name: `Dangerous Permission: ${permName.split('.').pop()}`,
                            severity: "Medium",
                            description: `${permData.description || permName} - ${permData.info || ''}`,
                            tool: "mobsf",
                        });
                    }
                });
            }
        }

        // --- Format 2: summary.findings structure (legacy) ---
        const summary = data?.summary;
        const findings = summary?.findings;
        if (findings) {
            console.log("[MobSF Parser] Found summary.findings object, parsing...");

            const categories = ['high', 'warning', 'hotspot', 'info', 'secure'];
            const severityMap: Record<string, "Critical" | "High" | "Medium" | "Low" | "Info"> = {
                high: "High",
                warning: "Medium",
                hotspot: "Medium",
                info: "Info",
                secure: "Info"
            };

            categories.forEach(category => {
                if (Array.isArray(findings[category])) {
                    findings[category].forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-${vulnIdx++}`,
                            name: category === 'secure' ? `✓ ${finding.title || "Secure"}` : finding.title || "Finding",
                            severity: severityMap[category],
                            description: finding.description || "No description available",
                            tool: "mobsf",
                        });
                    });
                }
            });
        }

        console.log(`[MobSF Parser] Parsed ${vulnerabilities.length} findings`);
        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing MobSF results:", error);
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
            case "mobsf":
                return parseMobsfResults(rawResult);
            default:
                console.warn(`No parser available for tool: ${tool}`);
                return [];
        }
    } catch (error) {
        console.error(`Error parsing ${tool} results:`, error);
        return [];
    }
}
