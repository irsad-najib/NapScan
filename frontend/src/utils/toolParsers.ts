/**
 * Tool Result Parsers
 * Centralized parsers for all scanning tools
 */

import { ScanVulnerability } from "@/context/ScanContext";
import { ToolKey } from "@/services/api";

import { extractAlerts } from "./zapParser";
// Re-export Nmap parser
export { parseNmapResults, parseNmapAuto, parseRawNmapScan } from "./nmapParser";
export type { ParsedNmapScanSummary, ParsedNmapHost, ParsedNmapPort } from "./nmapParser";

// Re-export ZAP parser
export { parseZapResults, parseZapAuto, parseZapResultsDetailed, analyzeZapRisk, extractAlerts } from "./zapParser";
export type { ParsedZapVulnerability, ZapRiskSummary, ZapAlert } from "./zapParser";

// Note: parseZapResults is now exported from ./zapParser

/**
 * Parse OpenVAS results - handles various response formats
 */
export function parseOpenVasResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        // Handle stringified JSON
        if (typeof rawResult === "string") {
            try {
                rawResult = JSON.parse(rawResult);
            } catch (e) {
                console.error("[OpenVAS Parser] Failed to parse stringified JSON:", e);
            }
        }

        console.log("[OpenVAS Parser] Raw result type:", typeof rawResult);
        console.log("[OpenVAS Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        let results: any[] = [];

        // Handle different possible structures
        // Format 1: { results: { result: [...] } } (standard OpenVAS format)
        if (rawResult?.results?.result && Array.isArray(rawResult.results.result)) {
            results = rawResult.results.result;
        }
        // Format 2: { data: { results: { result: [...] } } } (wrapped format)
        else if (rawResult?.data?.results?.result && Array.isArray(rawResult.data.results.result)) {
            results = rawResult.data.results.result;
        }
        // Format 3: { results: [...] } (simplified format)
        else if (Array.isArray(rawResult?.results)) {
            results = rawResult.results;
        }
        // Format 4: { result: [...] } (direct result array)
        else if (Array.isArray(rawResult?.result)) {
            results = rawResult.result;
        }
        // Format 5: Direct array
        else if (Array.isArray(rawResult)) {
            results = rawResult;
        }

        console.log("[OpenVAS Parser] Found", results.length, "results to parse");

        // Filter out "Log" level findings if there are other findings
        // or keep them if they're the only findings
        const hasRealFindings = results.some(r => {
            const threat = (r.threat || "").toLowerCase();
            return threat !== "log" && threat !== "";
        });

        results.forEach((result: any, idx: number) => {
            const threat = (result.threat || "").toLowerCase();
            const cvssScore = parseFloat(result.severity || result.nvt?.cvss_base || "0");

            let severity: "Critical" | "High" | "Medium" | "Low" | "Info" = "Info";

            // Map OpenVAS threat levels to our severity
            if (threat === "critical" || cvssScore >= 9.0) {
                severity = "Critical";
            } else if (threat === "high" || cvssScore >= 7.0) {
                severity = "High";
            } else if (threat === "medium" || cvssScore >= 4.0) {
                severity = "Medium";
            } else if (threat === "low" || cvssScore >= 0.1) {
                severity = "Low";
            } else {
                // "Log" or empty threat = Info
                severity = "Info";
            }

            // Skip "Log" level findings if we have real vulnerabilities
            // to avoid cluttering the results
            if (hasRealFindings && threat === "log" && cvssScore === 0) {
                return;
            }

            const name = result.name || result.nvt?.name || "OpenVAS Finding";
            const host = result.host || "";
            const port = result.port || "";
            const description = result.description || "";
            const nvtFamily = result.nvt?.family || "";
            const nvtOid = result.nvt?.oid || "";

            // Build a more informative description
            let fullDescription = description;
            if (!fullDescription && result.nvt?.tags) {
                // Try to extract summary from tags
                const tagsStr = result.nvt.tags;
                const summaryMatch = tagsStr.match(/summary=([^|]+)/);
                if (summaryMatch) {
                    fullDescription = summaryMatch[1].trim();
                }
            }
            if (!fullDescription) {
                fullDescription = `Detected on ${host}:${port}`;
            }

            // Extract solution from tags if available
            let solution = "";
            if (result.nvt?.tags) {
                const solutionMatch = result.nvt.tags.match(/solution=([^|]+)/);
                if (solutionMatch && solutionMatch[1].trim()) {
                    solution = solutionMatch[1].trim();
                }
            }

            vulnerabilities.push({
                id: `openvas-${idx}`,
                name: name,
                severity,
                description: fullDescription,
                tool: "openvas",
                affectedAsset: port ? `${host}:${port}` : host,
                recommendation: solution,
            });
        });

        console.log("[OpenVAS Parser] Parsed", vulnerabilities.length, "vulnerabilities");
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
        // Handle stringified JSON (unless it's NDJSON string format which is handled later)
        // We only parse if it looks like a JSON object/array, not NDJSON
        if (typeof rawResult === "string" && (rawResult.trim().startsWith('[') || rawResult.trim().startsWith('{'))) {
            try {
                const parsed = JSON.parse(rawResult);
                // Only use parsed if it's not a single string (which might be NDJSON line)
                rawResult = parsed;
            } catch (e) {
                // Ignore, might be NDJSON or raw text
            }
        }

        console.log("[Nuclei Parser] Raw result type:", typeof rawResult);
        console.log("[Nuclei Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        let results: any[] = [];

        // Handle different possible structures
        // Format 1: Compact summary format { summary: { findings: [...] } }
        if (rawResult?.summary?.findings && Array.isArray(rawResult.summary.findings)) {
            console.log("[Nuclei Parser] Found compact summary format with", rawResult.summary.findings.length, "findings");
            results = rawResult.summary.findings;
        }
        // Format 2: Direct array of results or Array of objects with findings
        else if (Array.isArray(rawResult)) {
            // Check for new format: Array of objects with findings
            if (rawResult.length > 0 && rawResult[0]?.findings && Array.isArray(rawResult[0].findings)) {
                console.log("[Nuclei Parser] Found array of objects with findings");
                results = rawResult.flatMap((item: any) => item.findings || []);
            } else {
                results = rawResult;
            }
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

            // Handle compact format fields & new format fields
            const name = result.name || result.info?.name || result["template-id"] || result.templateID || result.template || "Nuclei Finding";
            // Check evidence.matched_at for new format
            const matchedAt = result.matched_at || result.evidence?.matched_at || result["matched-at"] || result.host || result.url || "";
            // Check evidence.template_id for new format
            const templateId = result.template_id || result.evidence?.template_id || result["template-id"] || result.templateID || "";
            const tags = result.tags || result.info?.tags || [];

            // Create unique key for deduplication
            const uniqueKey = `${templateId}:${matchedAt}`;
            if (seenFindings.has(uniqueKey)) {
                return; // Skip duplicate
            }
            seenFindings.add(uniqueKey);

            // For compact format, description is not available
            // New format has top-level description
            const description = result.description || result.info?.description ||
                (tags.length > 0 ? `Tags: ${tags.join(", ")}` : `Template: ${templateId}`);

            const matcherName = result["matcher-name"] || result.matcher_name || "";
            const references = result.info?.reference || result.evidence?.references || [];
            const remediation = result.remediation || result.info?.remediation || "";
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
 * Parse SSLyze results - handles both CLI text output and new JSON format
 */
export function parseSslyzeResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = 0;

    try {
        // Handle stringified JSON
        if (typeof rawResult === "string" && (rawResult.trim().startsWith('[') || rawResult.trim().startsWith('{'))) {
            try {
                rawResult = JSON.parse(rawResult);
            } catch (e) {
                // Ignore, might be raw text output (legacy format)
            }
        }

        console.log("[SSLyze Parser] Raw result type:", typeof rawResult);
        console.log("[SSLyze Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        // Check if it's the new JSON format with server_scan_results
        if (Array.isArray(rawResult) && rawResult.length > 0 && rawResult[0]?.server_scan_results) {
            console.log("[SSLyze Parser] Detected new JSON array format");
            return parseSslyzeJsonFormat(rawResult[0], vulnIdx);
        }

        // Check if it's directly server_scan_results array
        if (Array.isArray(rawResult) && rawResult.length > 0 && rawResult[0]?.connectivity_result) {
            console.log("[SSLyze Parser] Detected server_scan_results array format");
            return parseSslyzeServerScanResults(rawResult, vulnIdx);
        }

        // Check if it's the wrapper format with server_scan_results
        if (rawResult?.server_scan_results && Array.isArray(rawResult.server_scan_results)) {
            console.log("[SSLyze Parser] Detected JSON format with server_scan_results");
            return parseSslyzeServerScanResults(rawResult.server_scan_results, vulnIdx);
        }

        // Fallback to text parsing for legacy format
        let textOutput = "";
        if (typeof rawResult === "string") {
            textOutput = rawResult;
        } else if (typeof rawResult?.error === "string") {
            textOutput = rawResult.error;
        } else if (typeof rawResult?.output === "string") {
            textOutput = rawResult.output;
        } else if (typeof rawResult?.message === "string") {
            textOutput = rawResult.message;
        }

        console.log("[SSLyze Parser] Text output length:", textOutput.length);

        if (!textOutput || textOutput.length < 100) {
            console.log("[SSLyze Parser] No valid text output found");
            return vulnerabilities;
        }

        // Legacy text parsing (keep existing logic)
        if (textOutput.includes("TLS 1.0 Cipher Suites") &&
            textOutput.includes("The server accepted the following") &&
            textOutput.match(/\* TLS 1\.0 Cipher Suites:[\s\S]*?The server accepted the following \d+ cipher suites/)) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Deprecated TLS 1.0 Supported",
                severity: "Medium",
                description: "Server supports TLS 1.0 which is deprecated.",
                tool: "sslyze",
            });
        }

        if (textOutput.includes("TLS 1.1 Cipher Suites") &&
            textOutput.includes("The server accepted the following") &&
            textOutput.match(/\* TLS 1\.1 Cipher Suites:[\s\S]*?The server accepted the following \d+ cipher suites/)) {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Deprecated TLS 1.1 Supported",
                severity: "Medium",
                description: "Server supports TLS 1.1 which is deprecated.",
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
 * Parse SSLyze JSON format with server_scan_results
 */
function parseSslyzeJsonFormat(data: any, startIdx: number): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = startIdx;

    if (data.server_scan_results && Array.isArray(data.server_scan_results)) {
        return parseSslyzeServerScanResults(data.server_scan_results, vulnIdx);
    }

    return vulnerabilities;
}

/**
 * Parse server_scan_results array
 */
function parseSslyzeServerScanResults(serverScanResults: any[], startIdx: number): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = startIdx;

    serverScanResults.forEach((scanResult: any, serverIdx: number) => {
        const serverName = scanResult.network_configuration?.tls_server_name_indication || `Server ${serverIdx + 1}`;

        // Check connectivity
        if (scanResult.connectivity_status !== "COMPLETED") {
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: "Connection Failed",
                severity: "High",
                description: `Could not connect to ${serverName}: ${scanResult.connectivity_error_trace || "Unknown error"}`,
                tool: "sslyze",
                affectedAsset: serverName,
            });
            return;
        }

        const connectivity = scanResult.connectivity_result;
        const scanData = scanResult.scan_result;

        // Check TLS version
        if (connectivity?.highest_tls_version_supported) {
            const tlsVersion = connectivity.highest_tls_version_supported;
            vulnerabilities.push({
                id: `sslyze-${vulnIdx++}`,
                name: `TLS Version: ${tlsVersion}`,
                severity: "Info",
                description: `Server supports ${tlsVersion} with cipher ${connectivity.cipher_suite_supported || "unknown"}`,
                tool: "sslyze",
                affectedAsset: serverName,
            });

            // Check for deprecated TLS versions  
            if (tlsVersion === "TLS_1_0" || tlsVersion === "TLS 1.0") {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Deprecated TLS 1.0 Supported",
                    severity: "Medium",
                    description: "Server's highest TLS version is 1.0 which is deprecated.",
                    tool: "sslyze",
                    affectedAsset: serverName,
                });
            } else if (tlsVersion === "TLS_1_1" || tlsVersion === "TLS 1.1") {
                vulnerabilities.push({
                    id: `sslyze-${vulnIdx++}`,
                    name: "Deprecated TLS 1.1 Supported",
                    severity: "Medium",
                    description: "Server's highest TLS version is 1.1 which is deprecated.",
                    tool: "sslyze",
                    affectedAsset: serverName,
                });
            }
        }

        // Parse certificate info
        const certInfo = scanData?.certificate_info?.result;
        if (certInfo?.certificate_deployments) {
            certInfo.certificate_deployments.forEach((deployment: any, depIdx: number) => {
                // Check OCSP status
                if (deployment.ocsp_response) {
                    const ocsp = deployment.ocsp_response;
                    if (ocsp.certificate_status !== "GOOD") {
                        vulnerabilities.push({
                            id: `sslyze-${vulnIdx++}`,
                            name: `Certificate OCSP Status: ${ocsp.certificate_status}`,
                            severity: ocsp.certificate_status === "REVOKED" ? "Critical" : "High",
                            description: `Certificate OCSP status is ${ocsp.certificate_status}`,
                            tool: "sslyze",
                            affectedAsset: serverName,
                        });
                    }
                }

                // Check must-staple extension
                if (deployment.leaf_certificate_has_must_staple_extension && !deployment.ocsp_response) {
                    vulnerabilities.push({
                        id: `sslyze-${vulnIdx++}`,
                        name: "Missing OCSP Stapling",
                        severity: "Medium",
                        description: "Certificate has Must-Staple extension but no OCSP response was received",
                        tool: "sslyze",
                        affectedAsset: serverName,
                    });
                }

                // Check SCT count
                if (deployment.leaf_certificate_signed_certificate_timestamps_count !== undefined) {
                    const sctCount = deployment.leaf_certificate_signed_certificate_timestamps_count;
                    if (sctCount < 2) {
                        vulnerabilities.push({
                            id: `sslyze-${vulnIdx++}`,
                            name: "Low SCT Count",
                            severity: "Low",
                            description: `Certificate has ${sctCount} SCTs (recommended: 2+)`,
                            tool: "sslyze",
                            affectedAsset: serverName,
                        });
                    }
                }

                // Check path validation results
                if (deployment.path_validation_results) {
                    deployment.path_validation_results.forEach((validation: any) => {
                        const trustStore = validation.trust_store?.name || "Unknown";
                        if (!validation.was_validation_successful) {
                            vulnerabilities.push({
                                id: `sslyze-${vulnIdx++}`,
                                name: `Certificate Validation Failed (${trustStore})`,
                                severity: "High",
                                description: validation.validation_error || "Certificate validation failed",
                                tool: "sslyze",
                                affectedAsset: serverName,
                            });
                        }
                    });
                }

                // Extract certificate details
                const chain = deployment.verified_certificate_chain || deployment.received_certificate_chain;
                if (chain && chain.length > 0) {
                    const leafCert = chain[0];
                    const subject = leafCert.subject?.rfc4514_string || "Unknown";
                    const issuer = leafCert.issuer?.rfc4514_string || "Unknown";
                    const notAfter = leafCert.not_valid_after;
                    const keySize = leafCert.public_key?.key_size;
                    const algorithm = leafCert.public_key?.algorithm;

                    // Check expiration
                    if (notAfter) {
                        const expiryDate = new Date(notAfter);
                        const now = new Date();
                        const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

                        if (daysUntilExpiry < 0) {
                            vulnerabilities.push({
                                id: `sslyze-${vulnIdx++}`,
                                name: "Certificate Expired",
                                severity: "Critical",
                                description: `Certificate expired on ${notAfter}`,
                                tool: "sslyze",
                                affectedAsset: subject,
                            });
                        } else if (daysUntilExpiry < 30) {
                            vulnerabilities.push({
                                id: `sslyze-${vulnIdx++}`,
                                name: "Certificate Expiring Soon",
                                severity: "Medium",
                                description: `Certificate expires in ${daysUntilExpiry} days (${notAfter})`,
                                tool: "sslyze",
                                affectedAsset: subject,
                            });
                        }
                    }

                    // Check key size
                    if (algorithm === "RSAPublicKey" && keySize && keySize < 2048) {
                        vulnerabilities.push({
                            id: `sslyze-${vulnIdx++}`,
                            name: "Weak RSA Key Size",
                            severity: "High",
                            description: `RSA key size is ${keySize} bits (recommended: 2048+)`,
                            tool: "sslyze",
                            affectedAsset: subject,
                        });
                    }

                    // Add certificate info
                    vulnerabilities.push({
                        id: `sslyze-${vulnIdx++}`,
                        name: "Certificate Info",
                        severity: "Info",
                        description: `Subject: ${subject} | Issuer: ${issuer} | ${algorithm} ${keySize}-bit | Valid until: ${notAfter}`,
                        tool: "sslyze",
                        affectedAsset: serverName,
                    });
                }
            });
        }
    });

    console.log(`[SSLyze Parser] Found ${vulnerabilities.length} findings from JSON format`);
    return vulnerabilities;
}

/**
 * Parse Ffuf results - handles various response formats
 */
export function parseFfufResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    try {
        // Handle stringified JSON
        if (typeof rawResult === "string") {
            try {
                rawResult = JSON.parse(rawResult);
            } catch (e) {
                console.error("[FFUF Parser] Failed to parse stringified JSON:", e);
            }
        }

        console.log("[FFUF Parser] Raw result type:", typeof rawResult);
        console.log("[FFUF Parser] Raw result keys:", rawResult ? Object.keys(rawResult) : "null");

        // Handle different possible structures
        // Structure 1: New async format: array where each item has .results
        //   e.g., [{ commandline, config, results: [...] }]
        // Structure 2: { data: { results: [...] } } (API response)
        // Structure 3: { results: [...] } (direct)
        // Structure 4: Direct array of results
        let results: any[] = [];

        if (Array.isArray(rawResult)) {
            // Check if this is the new format where each item contains .results
            if (rawResult.length > 0 && rawResult[0]?.results && Array.isArray(rawResult[0].results)) {
                console.log("[FFUF Parser] Detected new format with nested results");
                // Flatten all results from all items
                rawResult.forEach(item => {
                    if (item.results && Array.isArray(item.results)) {
                        results.push(...item.results);
                    }
                });
            } else {
                // Direct array of results
                results = rawResult;
            }
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
 * Parse MobSF scan results - handles multiple API formats:
 * - Format 1: findings.mobsf (new combined scan response with certificate, manifest, findings, etc.)
 * - Format 2: report.android_api structure
 * - Format 3: summary.findings structure (legacy)
 */
export function parseMobsfResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = 0;

    try {
        console.log("[MobSF Parser] Parsing results...");
        console.log("[MobSF Parser] Raw result keys:", Object.keys(rawResult || {}));

        // Handle stringified JSON
        if (typeof rawResult === "string") {
            try {
                rawResult = JSON.parse(rawResult);
            } catch (e) {
                console.error("[MobSF Parser] Failed to parse stringified JSON:", e);
            }
        }

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

        // --- Format 1: findings.mobsf structure (new combined scan response) ---
        // Also checks result.mobsf for the format provided by user
        // Also checks if rawResult IS the mobsf object (has certificate/manifest)
        const mobsfData = rawResult?.findings?.mobsf || data?.findings?.mobsf || rawResult?.result?.mobsf || (rawResult?.certificate ? rawResult : null);
        if (mobsfData) {
            console.log("[MobSF Parser] Found findings.mobsf structure, parsing...");

            // Parse certificate findings
            const certificate = mobsfData?.certificate;
            if (certificate?.findings && Array.isArray(certificate.findings)) {
                certificate.findings.forEach((finding: any) => {
                    vulnerabilities.push({
                        id: `mobsf-cert-${vulnIdx++}`,
                        name: finding.title || "Certificate Issue",
                        severity: mapSeverity(finding.severity),
                        description: finding.description || "No description",
                        tool: "mobsf",
                        affectedAsset: "Certificate",
                    });
                });
            }

            // Parse manifest findings
            const manifest = mobsfData?.manifest;
            if (manifest?.findings && Array.isArray(manifest.findings)) {
                manifest.findings.forEach((finding: any) => {
                    // Strip HTML tags from title
                    const cleanTitle = (finding.title || "Manifest Issue").replace(/<[^>]*>/g, '').replace(/<br>/gi, ' - ');
                    vulnerabilities.push({
                        id: `mobsf-manifest-${vulnIdx++}`,
                        name: cleanTitle,
                        severity: mapSeverity(finding.severity),
                        description: finding.description || "No description",
                        tool: "mobsf",
                        affectedAsset: "AndroidManifest.xml",
                        recommendation: finding.rule ? `Rule: ${finding.rule}` : undefined,
                    });
                });
            }

            // Parse code/security findings
            const findings = mobsfData?.findings;
            if (findings) {
                // Parse high severity findings
                if (Array.isArray(findings.high)) {
                    findings.high.forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-high-${vulnIdx++}`,
                            name: finding.title || "High Severity Finding",
                            severity: "High",
                            description: finding.description || "No description",
                            tool: "mobsf",
                            affectedAsset: finding.section || "Code Analysis",
                        });
                    });
                }

                // Parse warning findings
                if (Array.isArray(findings.warning)) {
                    findings.warning.forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-warning-${vulnIdx++}`,
                            name: finding.title || "Warning",
                            severity: "Medium",
                            description: finding.description || "No description",
                            tool: "mobsf",
                            affectedAsset: finding.section || "Code Analysis",
                        });
                    });
                }

                // Parse hotspot findings
                if (Array.isArray(findings.hotspot)) {
                    findings.hotspot.forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-hotspot-${vulnIdx++}`,
                            name: finding.title || "Security Hotspot",
                            severity: "Medium",
                            description: finding.description || "No description",
                            tool: "mobsf",
                            affectedAsset: finding.section || "Permissions",
                        });
                    });
                }

                // Parse info findings
                if (Array.isArray(findings.info)) {
                    findings.info.forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-info-${vulnIdx++}`,
                            name: finding.title || "Info",
                            severity: "Info",
                            description: finding.description || "No description",
                            tool: "mobsf",
                            affectedAsset: finding.section || "Code Analysis",
                        });
                    });
                }

                // Parse secure findings (positive security measures)
                if (Array.isArray(findings.secure)) {
                    findings.secure.forEach((finding: any) => {
                        vulnerabilities.push({
                            id: `mobsf-secure-${vulnIdx++}`,
                            name: `✓ ${finding.title || "Secure"}`,
                            severity: "Info",
                            description: finding.description || "No description",
                            tool: "mobsf",
                            affectedAsset: finding.section || "Security",
                        });
                    });
                }
            }

            // Parse dangerous permissions
            const permissions = mobsfData?.permissions;
            if (permissions?.dangerous_sample && Array.isArray(permissions.dangerous_sample)) {
                permissions.dangerous_sample.forEach((perm: any) => {
                    vulnerabilities.push({
                        id: `mobsf-perm-${vulnIdx++}`,
                        name: `Dangerous Permission: ${perm.permission?.split('.').pop() || "Unknown"}`,
                        severity: "Medium",
                        description: `${perm.description || ""} - ${perm.info || ""}`.trim(),
                        tool: "mobsf",
                        affectedAsset: perm.permission || "Permission",
                        recommendation: `Protection level: ${perm.protection || "unknown"}`,
                    });
                });
            }

            // Parse secrets if total > 0
            const secrets = mobsfData?.secrets;
            if (secrets?.total > 0 && secrets?.sample && Array.isArray(secrets.sample)) {
                vulnerabilities.push({
                    id: `mobsf-secrets-${vulnIdx++}`,
                    name: `Hardcoded Secrets Detected (${secrets.total} found)`,
                    severity: "High",
                    description: `Found ${secrets.total} potential hardcoded secrets. Sample: ${secrets.sample.slice(0, 3).join(", ")}...`,
                    tool: "mobsf",
                    affectedAsset: "Source Code",
                    recommendation: "Review and remove hardcoded secrets. Use environment variables or secure storage.",
                });
            }

            // Parse trackers
            const trackers = mobsfData?.trackers;
            if (trackers?.detected_trackers > 0) {
                vulnerabilities.push({
                    id: `mobsf-trackers-${vulnIdx++}`,
                    name: `Privacy Trackers Detected (${trackers.detected_trackers} found)`,
                    severity: "Medium",
                    description: `Application contains ${trackers.detected_trackers} out of ${trackers.total_trackers} known trackers.`,
                    tool: "mobsf",
                    affectedAsset: "Application",
                    recommendation: "Review tracker usage and ensure compliance with privacy regulations.",
                });
            }

            // Check for suspicious domains
            const network = mobsfData?.network;
            if (network?.suspicious_domains && network.suspicious_domains.length > 0) {
                vulnerabilities.push({
                    id: `mobsf-network-${vulnIdx++}`,
                    name: `Suspicious Domains Detected (${network.suspicious_domains.length} found)`,
                    severity: "High",
                    description: `Application communicates with suspicious domains: ${network.suspicious_domains.slice(0, 5).join(", ")}`,
                    tool: "mobsf",
                    affectedAsset: "Network",
                    recommendation: "Review and validate all external domain communications.",
                });
            }

            console.log(`[MobSF Parser] Parsed ${vulnerabilities.length} findings from findings.mobsf`);
            return vulnerabilities;
        }

        // --- Format 2: report.android_api structure ---
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

        // --- Format 3: summary.findings structure (legacy) ---
        const summary = data?.summary;
        const legacyFindings = summary?.findings;
        if (legacyFindings) {
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
                if (Array.isArray(legacyFindings[category])) {
                    legacyFindings[category].forEach((finding: any) => {
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

        // --- Integrated Frida Parsing ---
        // Check for Frida findings in the same result (combined scan)
        if (data?.findings?.frida) {
            console.log("[MobSF Parser] Found nested Frida findings, parsing...");
            const fridaVulns = parseFridaResults({ findings: { frida: data.findings.frida } });

            // Add Frida findings to the list, ensuring they are tagged properly
            // We keep the tool as 'mobsf' so they appear in the ToolRow, but add a tag for filtering
            fridaVulns.forEach(v => {
                v.tool = "mobsf";
                v.tags = (v.tags || []).concat(["frida"]);
                vulnerabilities.push(v);
            });
            console.log(`[MobSF Parser] Added ${fridaVulns.length} Frida findings`);
        }

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing MobSF results:", error);
        return [];
    }
}

/**
 * Parse Frida dynamic analysis events
 * Extracts security-relevant findings from Frida runtime analysis
 */
export function parseFridaResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    let vulnIdx = 0;

    try {
        console.log("[Frida Parser] Parsing results...");
        console.log("[Frida Parser] Raw result keys:", Object.keys(rawResult || {}));

        // Handle nested structure: findings.frida or direct frida object
        const fridaData = rawResult?.findings?.frida || rawResult?.frida || rawResult;

        if (!fridaData) {
            console.log("[Frida Parser] No frida data found");
            return vulnerabilities;
        }

        const events = fridaData?.events || [];
        const packageName = fridaData?.package_name || "Unknown Package";

        console.log(`[Frida Parser] Found ${events.length} events for ${packageName}`);

        // Track loaded modules and installed hooks for analysis
        const loadedModules: string[] = [];
        const installedHooks: Map<string, { class: string; method: string; overloads: number }[]> = new Map();
        let engineReady = false;
        let engineVersion = "";

        // Process events
        events.forEach((event: any) => {
            const eventType = event.event;
            const eventData = event.data || {};
            const timestamp = event.timestamp;

            switch (eventType) {
                case "engine_start":
                    engineVersion = eventData.version || "unknown";
                    break;

                case "module_loaded":
                    const moduleName = eventData.name;
                    if (moduleName) {
                        loadedModules.push(moduleName);
                    }
                    break;

                case "hook_installed":
                    const hookClass = eventData.class || "";
                    const hookMethod = eventData.method || "";
                    const overloads = eventData.overloads || 1;

                    // Group hooks by module context (based on class patterns)
                    let moduleContext = "other";
                    if (hookClass.includes("ssl") || hookClass.includes("TrustManager") || hookClass.includes("CertificatePinner")) {
                        moduleContext = "ssl_pinning";
                    } else if (hookClass.includes("Debug")) {
                        moduleContext = "anti_debug";
                    } else if (hookClass.includes("Runtime")) {
                        moduleContext = "root";
                    } else if (hookClass.includes("Cipher") || hookClass.includes("crypto")) {
                        moduleContext = "crypto";
                    } else if (hookClass.includes("SQLite") || hookClass.includes("database")) {
                        moduleContext = "storage";
                    } else if (hookClass.includes("WebView")) {
                        moduleContext = "webview";
                    }

                    if (!installedHooks.has(moduleContext)) {
                        installedHooks.set(moduleContext, []);
                    }
                    installedHooks.get(moduleContext)!.push({ class: hookClass, method: hookMethod, overloads });
                    break;

                case "engine_ready":
                    engineReady = true;
                    break;

                case "module_decision":
                    const category = eventData.category;
                    const moduleDecision = eventData.module;
                    const enabled = eventData.enabled;

                    if (category === "detection" && enabled) {
                        vulnerabilities.push({
                            id: `frida-decision-${vulnIdx++}`,
                            name: `Security Detection Active: ${moduleDecision}`,
                            severity: "Info",
                            description: `The application has active ${moduleDecision} detection mechanisms. Frida attempted to bypass these.`,
                            tool: "frida",
                            affectedAsset: packageName,
                            tags: ["frida-bypass"]
                        });
                    }
                    break;
            }
        });

        // Generate security findings based on what Frida detected

        // SSL Pinning Analysis
        const sslHooks = installedHooks.get("ssl_pinning") || [];
        if (sslHooks.length > 0) {
            const sslClasses = sslHooks.map(h => h.class).join(", ");
            vulnerabilities.push({
                id: `frida-ssl-${vulnIdx++}`,
                name: "SSL Certificate Pinning Detected",
                severity: "Info",
                description: `Frida successfully hooked SSL pinning mechanisms. Classes monitored: ${sslClasses}. This indicates the app implements certificate pinning which can be bypassed.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Certificate pinning is a good security measure, but can be bypassed with Frida. Consider implementing additional tamper detection.",
            });
        }

        // Anti-Debug Analysis
        const debugHooks = installedHooks.get("anti_debug") || [];
        if (debugHooks.length > 0) {
            vulnerabilities.push({
                id: `frida-debug-${vulnIdx++}`,
                name: "Anti-Debug Mechanisms Hooked",
                severity: "Info",
                description: `Frida hooked anti-debugging functions: ${debugHooks.map(h => `${h.class}.${h.method}`).join(", ")}. App checks for debugger can be bypassed.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Implement multiple layers of anti-tampering and obfuscation.",
            });
        }

        // Root Detection Analysis
        const rootHooks = installedHooks.get("root") || [];
        if (rootHooks.length > 0) {
            vulnerabilities.push({
                id: `frida-root-${vulnIdx++}`,
                name: "Root Detection Hooked",
                severity: "Info",
                description: `Frida hooked potential root detection mechanisms via: ${rootHooks.map(h => `${h.class}.${h.method}`).join(", ")}. Runtime.exec calls are monitored.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Root detection alone is not sufficient. Implement integrity checks and use hardware-backed security.",
            });
        }

        // Crypto Analysis
        const cryptoHooks = installedHooks.get("crypto") || [];
        if (cryptoHooks.length > 0) {
            vulnerabilities.push({
                id: `frida-crypto-${vulnIdx++}`,
                name: "Cryptographic Operations Monitored",
                severity: "Medium",
                description: `Frida is monitoring cryptographic operations: ${cryptoHooks.map(h => `${h.class}.${h.method}`).join(", ")}. Encryption keys and operations can be intercepted.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Use hardware-backed keystore and avoid storing sensitive keys in memory longer than necessary.",
            });
        }

        // Storage Analysis
        const storageHooks = installedHooks.get("storage") || [];
        if (storageHooks.length > 0) {
            vulnerabilities.push({
                id: `frida-storage-${vulnIdx++}`,
                name: "Database Operations Monitored",
                severity: "Medium",
                description: `Frida is monitoring database operations: ${storageHooks.map(h => `${h.class}.${h.method}`).join(", ")}. Database contents and queries can be intercepted.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Encrypt sensitive data before storing in SQLite. Use SQLCipher for database encryption.",
            });
        }

        // WebView Analysis
        const webviewHooks = installedHooks.get("webview") || [];
        if (webviewHooks.length > 0) {
            vulnerabilities.push({
                id: `frida-webview-${vulnIdx++}`,
                name: "WebView Activity Monitored",
                severity: "Medium",
                description: `Frida is monitoring WebView operations: ${webviewHooks.map(h => `${h.class}.${h.method}`).join(", ")}. URLs loaded in WebView can be intercepted.`,
                tool: "frida",
                affectedAsset: packageName,
                recommendation: "Implement secure WebView configuration. Disable JavaScript if not needed, and validate URLs before loading.",
            });
        }

        // Overall Dynamic Analysis Summary
        if (loadedModules.length > 0) {
            vulnerabilities.push({
                id: `frida-summary-${vulnIdx++}`,
                name: "Dynamic Analysis Summary",
                severity: "Info",
                description: `Frida engine v${engineVersion} successfully attached and loaded ${loadedModules.length} modules: ${loadedModules.join(", ")}. Total hooks installed: ${Array.from(installedHooks.values()).flat().length}.`,
                tool: "frida",
                affectedAsset: packageName,
            });
        }

        console.log(`[Frida Parser] Parsed ${vulnerabilities.length} findings`);
        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Frida results:", error);
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
            case "frida":
                return parseFridaResults(rawResult);
            default:
                console.warn(`No parser available for tool: ${tool}`);
                return [];
        }
    } catch (error) {
        console.error(`Error parsing ${tool} results:`, error);
        return [];
    }
}

/**
 * Parse combined MobSF + Frida scan results
 * Used when the scan is completed with both static (MobSF) and dynamic (Frida) analysis
 */
export function parseCombinedMobsfFridaResults(rawResult: any): {
    mobsfFindings: ScanVulnerability[];
    fridaFindings: ScanVulnerability[];
    combined: ScanVulnerability[];
    appInfo: MobSFAppInfo | null;
} {
    const mobsfFindings = parseMobsfResults(rawResult);
    const fridaFindings = parseFridaResults(rawResult);

    return {
        mobsfFindings,
        fridaFindings,
        combined: [...mobsfFindings, ...fridaFindings],
        appInfo: extractMobsfAppInfo(rawResult),
    };
}

/**
 * App info extracted from MobSF results
 */
export interface MobSFAppInfo {
    appName: string;
    packageName: string;
    versionName: string;
    fileName: string;
    iconPath?: string;
    securityScore: string;
    minSdk: string;
    targetSdk: string;
    maxSdk?: string;
    hashes: {
        md5: string;
        sha1: string;
        sha256: string;
    };
    components: {
        activities: number;
        services: number;
        receivers: number;
        providers: number;
        exportedActivities: number;
        exportedServices: number;
        exportedReceivers: number;
        exportedProviders: number;
    };
    network: {
        domainsTotal: number;
        urlsTotal: number;
        domainsSample: string[];
        suspiciousDomains: string[];
    };
    permissions: {
        dangerousCount: number;
        normalCount: number;
        unknownCount: number;
    };
    trackers: {
        detected: number;
        total: number;
    };
}

/**
 * Extract app information from MobSF results
 */
export function extractMobsfAppInfo(rawResult: any): MobSFAppInfo | null {
    try {
        const mobsfData = rawResult?.findings?.mobsf || rawResult?.mobsf;

        if (!mobsfData) {
            console.log("[MobSF] No mobsf data found for app info extraction");
            return null;
        }

        const identity = mobsfData?.identity || {};
        const sdk = mobsfData?.sdk || {};
        const hashes = mobsfData?.hashes || {};
        const components = mobsfData?.components || {};
        const network = mobsfData?.network || {};
        const permissions = mobsfData?.permissions || {};
        const trackers = mobsfData?.trackers || {};
        const findings = mobsfData?.findings || {};

        return {
            appName: identity.app_name || "Unknown",
            packageName: identity.package_name || "Unknown",
            versionName: identity.version_name || "Unknown",
            fileName: identity.file_name || "Unknown",
            iconPath: identity.icon_path,
            securityScore: findings.security_score || "N/A",
            minSdk: sdk.min_sdk || "Unknown",
            targetSdk: sdk.target_sdk || "Unknown",
            maxSdk: sdk.max_sdk,
            hashes: {
                md5: hashes.md5 || "",
                sha1: hashes.sha1 || "",
                sha256: hashes.sha256 || "",
            },
            components: {
                activities: components.activities || 0,
                services: components.services || 0,
                receivers: components.receivers || 0,
                providers: components.providers || 0,
                exportedActivities: components.exported_count?.exported_activities || 0,
                exportedServices: components.exported_count?.exported_services || 0,
                exportedReceivers: components.exported_count?.exported_receivers || 0,
                exportedProviders: components.exported_count?.exported_providers || 0,
            },
            network: {
                domainsTotal: network.domains_total || 0,
                urlsTotal: network.urls_total || 0,
                domainsSample: network.domains_sample || [],
                suspiciousDomains: network.suspicious_domains || [],
            },
            permissions: {
                dangerousCount: permissions.status_counts?.dangerous || 0,
                normalCount: permissions.status_counts?.normal || 0,
                unknownCount: permissions.status_counts?.unknown || 0,
            },
            trackers: {
                detected: trackers.detected_trackers || 0,
                total: trackers.total_trackers || 0,
            },
        };
    } catch (error) {
        console.error("Error extracting MobSF app info:", error);
        return null;
    }
}

/**
 * Normalize severity strings to standard format
 */
function normalizeSeverity(input: string): "Critical" | "High" | "Medium" | "Low" | "Info" {
    const s = (input || "").toLowerCase();
    if (s.includes("critical") || s.includes("danger")) return "Critical";
    if (s.includes("high")) return "High";
    if (s.includes("medium") || s.includes("war") || s.includes("warn")) return "Medium"; // Matches warning
    if (s.includes("low") || s.includes("hotspot")) return "Low"; // Matches hotspot
    return "Info";
}

/**
 * Extract tabular data for the ParsedResultTable component
 */
export function getToolTableData(tool: ToolKey | string, result: any): any[] {
    if (!result) return [];

    try {
        switch (tool) {
            case 'nmap':
                return getNmapTableData(result);
            case 'ffuf':
                return getFfufTableData(result);
            case 'zap':
                return getZapTableData(result);
            case 'nuclei':
                return getNucleiTableData(result);
            case 'sslyze':
                return getSslyzeTableData(result);
            case 'mobsf':
                // MobSF usually returns complex object, we might want to show specific parts
                return getMobsfTableData(result);
            case 'openvas':
                return getOpenVasTableData(result);
            default:
                return [];
        }
    } catch (error) {
        console.error(`Error getting table data for ${tool}:`, error);
        return [];
    }
}

function getNmapTableData(result: any): any[] {
    // Reuse the normalization logic from parseNmapAuto/normalizeNmapResult
    // But we need to handle the customized format that likely comes from the API result.risks OR the raw scan
    // Ideally we want to show Ports if available

    // Check if we have raw structure availability (preferred for table view)
    let rawData = result;

    // Helper to calculate severity
    const getSeverity = (port: number, service: string, state: string): "Critical" | "High" | "Medium" | "Low" | "Info" => {
        // Filtered ports are informational
        if (state.includes("filtered") && !state.includes("open")) {
            return "Info";
        }

        // Critical: Well-known vulnerable services
        const criticalPorts = [23, 69, 161, 445, 512, 513, 514, 1433, 1434, 3389];
        if (criticalPorts.includes(port)) return "Critical";

        // High: Database and admin ports
        const highPorts = [21, 3306, 5432, 27017, 6379, 9200, 5900, 5901, 8080, 8443];
        if (highPorts.includes(port)) return "High";

        // Services that are inherently risky
        const riskyServices = ["telnet", "tftp", "snmp", "rdp", "vnc", "ftp"];
        if (riskyServices.some(s => service.toLowerCase().includes(s))) return "High";

        // Medium: Standard web and encrypted services
        const mediumPorts = [80, 443, 8000, 8888, 9000];
        if (mediumPorts.includes(port)) return "Medium";

        // Low: Common safe services
        const lowPorts = [22, 25, 53, 110, 143, 993, 995];
        if (lowPorts.includes(port)) return "Low";

        // Default for open|filtered UDP ports
        if (state === "open|filtered") return "Low";

        return "Info";
    };

    // Handle "risks" format (API processed) - this doesn't have all ports usually, only risks
    // But we might have the full map in result directly if it was passed raw

    // Try to normalize using the internal logic if possible, or just parse manully
    const hosts: any[] = [];

    const parsePorts = (hostPorts: any[], protocol: string) => {
        return hostPorts.map(p => {
            const portNum = parseInt(p.port);
            const service = p.Service?.name || 'unknown';
            const state = p.State?.state || 'unknown';

            return {
                port: p.port,
                protocol: protocol,
                state: state,
                service: service,
                version: p.Service?.product ? `${p.Service.product} ${p.Service.version || ''}` : '',
                severity: getSeverity(portNum, service, state)
            };
        });
    };

    // Helper to traverse the raw nmap structure
    const processHosts = (hostList: any[], protocol: string) => {
        if (!Array.isArray(hostList)) return [];
        return hostList.flatMap(host => {
            if (host.ports?.ports) {
                return parsePorts(host.ports.ports, protocol);
            }
            return [];
        });
    };

    // Check for new nested format { tcp: [{ tcp: {...}, udp: {...} }] }
    if (Array.isArray(rawData?.tcp) && rawData.tcp.length > 0 && (rawData.tcp[0]?.tcp || rawData.tcp[0]?.udp)) {
        const items = rawData.tcp;
        let findings: any[] = [];
        items.forEach((item: any) => {
            if (item.tcp?.hosts) findings = [...findings, ...processHosts(item.tcp.hosts, 'tcp')];
            if (item.udp?.hosts) findings = [...findings, ...processHosts(item.udp.hosts, 'udp')];
        });
        return findings;
    }

    // Standard raw format
    let findings: any[] = [];
    if (rawData?.tcp?.hosts) findings = [...findings, ...processHosts(rawData.tcp.hosts, 'tcp')];
    if (rawData?.udp?.hosts) findings = [...findings, ...processHosts(rawData.udp.hosts, 'udp')];

    if (findings.length > 0) return findings;

    // Fallback: if we only have risks (processed data)
    if (result?.risks) {
        const risks = [...(result.risks.new_open || []), ...(result.risks.still_open || [])];
        const riskFindings: any[] = [];

        risks.forEach((r: any) => {
            // Check if risk has nested findings (common in aggregated reports)
            if (r.findings && Array.isArray(r.findings)) {
                r.findings.forEach((f: any) => {
                    // Try to extract port from finding name/description/location
                    const portMatch = (f.name || f.description || f.location || '').match(/(?:port|:)\s*(\d+)/i);
                    riskFindings.push({
                        port: portMatch ? portMatch[1] : '-',
                        protocol: (f.name || '').toLowerCase().includes('udp') ? 'udp' : 'tcp',
                        state: 'open', // Assumed if it's a finding
                        service: f.service || 'unknown',
                        version: f.description || f.name,
                        severity: normalizeSeverity(f.severity || r.threat_level)
                    });
                });
            } else {
                // Single risk item
                riskFindings.push({
                    port: r.title.match(/Port:\s*(\d+)/)?.[1] || '-',
                    protocol: r.title.toLowerCase().includes('udp') ? 'udp' : 'tcp',
                    state: 'open',
                    service: 'unknown',
                    version: r.title,
                    severity: normalizeSeverity(r.threat_level)
                });
            }
        });

        return riskFindings;
    }

    return [];
}

function getFfufTableData(result: any): any[] {
    let results: any[] = [];

    // Handle new format where result is array of objects with .results
    if (Array.isArray(result)) {
        if (result.length > 0 && result[0]?.results) {
            result.forEach(item => {
                if (Array.isArray(item.results)) results.push(...item.results);
            });
        } else {
            results = result;
        }
    } else if (result?.results) {
        results = result.results;
    } else if (result?.data?.results) {
        results = result.data.results;
    }

    return results.map((r: any) => ({
        path: r.input?.FUZZ || r.url,
        status: r.status || r.statuscode,
        size: r.length,
        words: r.words,
        lines: r.lines,
        type: 'file' // Ffuf usually finds files/directories
    }));
}

function getZapTableData(result: any): any[] {
    // Use the centralized extractAlerts function to handle all ZAP formats
    let alerts = extractAlerts(result);

    // Fallback: Check for nested alertsRaw.alerts structure explicitly if extractAlerts returned nothing
    // This handles the case where the result structure might be slightly different than what extractAlerts expects
    if ((!alerts || alerts.length === 0) && result?.alertsRaw?.alerts) {
        console.log("[ToolParsers] Using direct alertsRaw.alerts fallback for ZAP");
        alerts = result.alertsRaw.alerts;
    }

    // Fallback: Check for data.alertsRaw.alerts
    if ((!alerts || alerts.length === 0) && result?.data?.alertsRaw?.alerts) {
        console.log("[ToolParsers] Using direct data.alertsRaw.alerts fallback for ZAP");
        alerts = result.data.alertsRaw.alerts;
    }

    // Ensure alerts is an array
    if (!Array.isArray(alerts)) {
        return [];
    }

    return alerts.map((a: any) => ({
        alert: a.alert || a.name,
        // Use normalized severity
        risk: normalizeSeverity(a.risk || a.riskdesc?.split(' ')[0] || "Info"),
        confidence: a.confidence,
        method: a.method,
        url: a.url
    }));
}

function getNucleiTableData(result: any): any[] {
    // Re-use logic from parseNucleiResults roughly but keep it simple for table
    let findings: any[] = [];

    // Check for different Nuclei formats
    if (Array.isArray(result)) {
        if (result.length > 0 && result[0]?.findings) {
            findings = result.flatMap((r: any) => r.findings || []);
        } else {
            findings = result;
        }
    } else if (result?.summary?.findings) {
        findings = result.summary.findings;
    } else if (result?.data?.results) {
        findings = result.data.results;
    } else if (typeof result?.output === 'string') {
        try {
            findings = result.output.split('\n').filter((l: string) => l.trim()).map(JSON.parse);
        } catch (e) { /* ignore */ }
    }

    return findings.map((f: any) => ({
        template: f['template-id'] || f.templateID || f.info?.name,
        severity: normalizeSeverity(f.info?.severity || f.severity || "info"),
        name: f.info?.name || f.name,
        matched_at: f['matched-at'] || f.matched_at || f.host,
        timestamp: f.timestamp
    }));
}

function getSslyzeTableData(result: any): any[] {
    // Flatten SSLyze structure
    // We typically want to show: Check Name | Value/Status
    const rows: any[] = [];

    // Handle array format (likely from our backend wrapper or direct JSON output)
    let scanResult = result;
    if (Array.isArray(result) && result.length > 0) scanResult = result[0];

    // Navigate to server_scan_results
    const serverResults = scanResult?.server_scan_results || (scanResult?.connectivity_result ? [scanResult] : []);

    if (Array.isArray(serverResults)) {
        serverResults.forEach((server: any) => {
            const scanData = server.scan_result;
            if (!scanData) return;

            // Certificate Info
            const certDeployments = scanData.certificate_info?.result?.certificate_deployments;
            if (certDeployments) {
                certDeployments.forEach((dep: any, idx: number) => {
                    const leaf = dep.verified_certificate_chain?.[0] || dep.received_certificate_chain?.[0];
                    if (leaf) {
                        rows.push({
                            property: `Certificate Subject (${idx + 1})`,
                            value: leaf.subject?.rfc4514_string || 'Unknown',
                            severity: 'Info'
                        });
                        rows.push({
                            property: `Certificate Not After (${idx + 1})`,
                            value: leaf.not_valid_after,
                            severity: 'Info'
                        });
                    }
                });
            }

            // Cipher Suites (Simplified)
            // Accessing different scan commands
            if (scanData.ssl_2_0_cipher_suites?.result?.is_vulnerable_to_client_renegotiation_dos) { // Just example check
                rows.push({ property: 'SSL 2.0', value: 'Supported', severity: 'Critical' });
            }
            // ... Add more parsers as needed, but SSLyze JSON is huge. 
            // Only adding basic connectivity info for now + what we parsed before
        });
    }

    // Fallback: if we just have a subset or different format, try to extract basic info
    if (rows.length === 0 && result) {
        // Could parse the text execution if it failed...
    }

    return rows;
}

function getMobsfTableData(result: any): any[] {
    const rows: any[] = [];
    const data = result?.data || result;

    // Flatten findings
    const mobsfFindings = data?.findings?.mobsf || data?.summary;

    if (mobsfFindings) {
        // High/Warning/Secure/Hotspot
        ['high', 'warning', 'hotspot', 'secure'].forEach(sev => {
            if (Array.isArray(mobsfFindings[sev])) {
                mobsfFindings[sev].forEach((f: any) => {
                    // Map MobSF severity keys to our standard
                    let standardSeverity = normalizeSeverity(sev); // warning->Medium, hotspot->Low

                    rows.push({
                        title: f.title,
                        severity: standardSeverity,
                        component: f.section || f.file_path,
                        description: f.description
                    });
                });
            }
        });

        // Manifest
        if (mobsfFindings.manifest?.findings) {
            mobsfFindings.manifest.findings.forEach((f: any) => {
                rows.push({
                    title: f.title,
                    severity: normalizeSeverity(f.severity),
                    component: 'AndroidManifest.xml',
                    description: f.description
                });
            });
        }
    }

    return rows;
}

function getOpenVasTableData(result: any): any[] {
    // Helper to traverse OpenVAS structure
    let findings: any[] = [];

    // Check for standard XML-converted format
    // result.report?.results?.result
    if (result?.report?.results?.result) {
        const res = result.report.results.result;
        if (Array.isArray(res)) {
            findings = res;
        } else {
            findings = [res];
        }
    }
    // Format: { results: { result: [...] } }
    else if (result?.results?.result && Array.isArray(result.results.result)) {
        findings = result.results.result;
    }
    // Format: { data: { results: { result: [...] } } }
    else if (result?.data?.results?.result && Array.isArray(result.data.results.result)) {
        findings = result.data.results.result;
    }
    // Fallback: direct array
    else if (Array.isArray(result)) {
        findings = result;
    }

    // Filter out "Log" level findings if there are other findings
    const hasRealFindings = findings.some((r: any) => {
        const threat = (r.threat || "").toLowerCase();
        const severity = parseFloat(r.severity || "0");
        return threat !== "log" && threat !== "" && severity > 0;
    });

    return findings
        .filter((f: any) => {
            const threat = (f.threat || "").toLowerCase();
            const score = parseFloat(f.severity || "0");
            // If we have real vulnerabilities, hide Log/Info (severity 0) items to reduce noise
            if (hasRealFindings && (threat === "log" || score === 0)) {
                return false;
            }
            return true;
        })
        .map((f: any) => {
            // Normalize severity using standard helper, but check score first if needed
            let severityInput = (f.threat || "").toLowerCase();
            const score = parseFloat(f.severity || "0");

            if (score >= 9.0) severityInput = "critical";
            else if (score >= 7.0) severityInput = "high";
            else if (score >= 4.0) severityInput = "medium";
            else if (score >= 0.1) severityInput = "low";

            return {
                name: f.name || f.nvt?.name || "Unknown Finding",
                severity: normalizeSeverity(severityInput), // Use our calculated one which matches the standard
                host: f.host?.['#text'] || f.host,
                port: f.port?.['#text'] || f.port,
                description: f.description
            };
        });
}
