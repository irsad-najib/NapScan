/**
 * Enhanced OWASP ZAP Result Parser
 * Converts raw ZAP API response into structured vulnerability findings
 * Supports the actual API response format with nested data structure
 */

import { ScanVulnerability } from "@/context/ScanContext";

// ============================================================================
// ZAP API RESPONSE INTERFACES
// ============================================================================

export interface ZapAlert {
    alert: string;
    alertRef: string;
    attack?: string;
    confidence: "High" | "Medium" | "Low" | "False Positive";
    cweid: string;
    description: string;
    evidence?: string;
    id: string;
    inputVector?: string;
    messageId?: string;
    method: string;
    name: string;
    nodeName?: string;
    other?: string;
    param?: string;
    pluginId: string;
    reference?: string;
    risk: "High" | "Medium" | "Low" | "Informational";
    solution: string;
    sourceMessageId?: number;
    sourceid?: string;
    tags?: Record<string, string>;
    url: string;
    wascid: string;
}

export interface ZapAlertsRaw {
    alerts: ZapAlert[];
}

export interface ZapActiveResult {
    scanId: string;
}

export interface ZapScanData {
    active?: ZapActiveResult;
    alertsRaw?: ZapAlertsRaw;
}

export interface ZapApiResponse {
    success: boolean;
    message: string;
    data: ZapScanData;
}

// ============================================================================
// PARSED TYPES
// ============================================================================

export interface ParsedZapVulnerability {
    id: string;
    name: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    description: string;
    tool: "zap";
    // Extended fields
    alertRef: string;
    pluginId: string;
    cweid: string;
    wascid: string;
    confidence: string;
    solution: string;
    evidence?: string;
    url: string;
    method: string;
    param?: string;
    reference?: string;
}

export interface ZapRiskSummary {
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    byConfidence: {
        high: number;
        medium: number;
        low: number;
    };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Map ZAP risk level to normalized severity
 */
function mapRiskToSeverity(risk: string): "Critical" | "High" | "Medium" | "Low" | "Info" {
    const normalized = risk.toLowerCase();

    if (normalized.includes("high")) return "High";
    if (normalized.includes("medium")) return "Medium";
    if (normalized.includes("low")) return "Low";
    if (normalized.includes("informational") || normalized.includes("info")) return "Info";

    return "Info";
}

/**
 * Extract alerts array from various response formats
 */
function extractAlerts(rawResult: any): ZapAlert[] {
    // Format 1: Full API response with data wrapper
    // { success: true, data: { alertsRaw: { alerts: [...] } } }
    if (rawResult?.data?.alertsRaw?.alerts) {
        return rawResult.data.alertsRaw.alerts;
    }

    // Format 2: Direct data object (after unwrapping)
    // { alertsRaw: { alerts: [...] } }
    if (rawResult?.alertsRaw?.alerts) {
        return rawResult.alertsRaw.alerts;
    }

    // Format 3: Direct alerts array in alertsRaw
    // { alertsRaw: [...] }
    if (Array.isArray(rawResult?.alertsRaw)) {
        return rawResult.alertsRaw;
    }

    // Format 4: Direct alerts array
    // { alerts: [...] }
    if (Array.isArray(rawResult?.alerts)) {
        return rawResult.alerts;
    }

    // Format 5: Raw array of alerts
    if (Array.isArray(rawResult)) {
        return rawResult;
    }

    console.warn("[ZapParser] Could not extract alerts from result:", rawResult);
    return [];
}

// ============================================================================
// PARSER FUNCTIONS
// ============================================================================

/**
 * Parse ZAP results into basic ScanVulnerability array
 */
export function parseZapResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    console.log("[ZapParser] Raw result received:", rawResult);

    try {
        const alerts = extractAlerts(rawResult);

        console.log(`[ZapParser] Found ${alerts.length} alerts`);

        alerts.forEach((alert: ZapAlert, idx: number) => {
            const severity = mapRiskToSeverity(alert.risk || "Informational");

            vulnerabilities.push({
                id: `zap-${alert.id || alert.alertRef || idx}`,
                name: alert.alert || alert.name || "Unknown ZAP Finding",
                severity,
                description: alert.description || "No description available",
                tool: "zap",
            });
        });

        console.log(`[ZapParser] Parsed ${vulnerabilities.length} vulnerabilities`);
        return vulnerabilities;
    } catch (error) {
        console.error("[ZapParser] Error parsing ZAP results:", error);
        return [];
    }
}

/**
 * Parse ZAP results with extended details
 */
export function parseZapResultsDetailed(rawResult: any): ParsedZapVulnerability[] {
    const vulnerabilities: ParsedZapVulnerability[] = [];

    try {
        const alerts = extractAlerts(rawResult);

        alerts.forEach((alert: ZapAlert, idx: number) => {
            const severity = mapRiskToSeverity(alert.risk || "Informational");

            vulnerabilities.push({
                id: `zap-${alert.id || alert.alertRef || idx}`,
                name: alert.alert || alert.name || "Unknown ZAP Finding",
                severity,
                description: alert.description || "No description available",
                tool: "zap",
                // Extended fields
                alertRef: alert.alertRef || "",
                pluginId: alert.pluginId || "",
                cweid: alert.cweid || "-1",
                wascid: alert.wascid || "-1",
                confidence: alert.confidence || "Medium",
                solution: alert.solution || "No solution provided",
                evidence: alert.evidence,
                url: alert.url || "",
                method: alert.method || "GET",
                param: alert.param,
                reference: alert.reference,
            });
        });

        return vulnerabilities;
    } catch (error) {
        console.error("[ZapParser] Error parsing ZAP results:", error);
        return [];
    }
}

/**
 * Analyze ZAP results and generate risk summary
 */
export function analyzeZapRisk(rawResult: any): ZapRiskSummary {
    const summary: ZapRiskSummary = {
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
        byConfidence: {
            high: 0,
            medium: 0,
            low: 0,
        },
    };

    try {
        const alerts = extractAlerts(rawResult);
        summary.total = alerts.length;

        alerts.forEach((alert: ZapAlert) => {
            // Count by risk
            const risk = (alert.risk || "").toLowerCase();
            if (risk.includes("high")) summary.high++;
            else if (risk.includes("medium")) summary.medium++;
            else if (risk.includes("low")) summary.low++;
            else summary.info++;

            // Count by confidence
            const confidence = (alert.confidence || "").toLowerCase();
            if (confidence.includes("high")) summary.byConfidence.high++;
            else if (confidence.includes("medium")) summary.byConfidence.medium++;
            else if (confidence.includes("low")) summary.byConfidence.low++;
        });

        return summary;
    } catch (error) {
        console.error("[ZapParser] Error analyzing ZAP risk:", error);
        return summary;
    }
}

/**
 * Group alerts by URL for better organization
 */
export function groupAlertsByUrl(rawResult: any): Map<string, ParsedZapVulnerability[]> {
    const groupedAlerts = new Map<string, ParsedZapVulnerability[]>();

    try {
        const parsed = parseZapResultsDetailed(rawResult);

        parsed.forEach(vuln => {
            const url = vuln.url || "Unknown URL";
            if (!groupedAlerts.has(url)) {
                groupedAlerts.set(url, []);
            }
            groupedAlerts.get(url)!.push(vuln);
        });

        return groupedAlerts;
    } catch (error) {
        console.error("[ZapParser] Error grouping alerts:", error);
        return groupedAlerts;
    }
}

/**
 * Group alerts by CWE ID for categorization
 */
export function groupAlertsByCwe(rawResult: any): Map<string, ParsedZapVulnerability[]> {
    const groupedAlerts = new Map<string, ParsedZapVulnerability[]>();

    try {
        const parsed = parseZapResultsDetailed(rawResult);

        parsed.forEach(vuln => {
            const cwe = vuln.cweid || "-1";
            if (!groupedAlerts.has(cwe)) {
                groupedAlerts.set(cwe, []);
            }
            groupedAlerts.get(cwe)!.push(vuln);
        });

        return groupedAlerts;
    } catch (error) {
        console.error("[ZapParser] Error grouping alerts by CWE:", error);
        return groupedAlerts;
    }
}

/**
 * Auto-detect format and parse accordingly
 */
export function parseZapAuto(rawResult: any): ScanVulnerability[] {
    console.log("[ZapParser] Auto-detecting ZAP result format");

    // Try to parse using the standard function
    const result = parseZapResults(rawResult);

    if (result.length > 0) {
        console.log(`[ZapParser] Successfully parsed ${result.length} vulnerabilities`);
    } else {
        console.log("[ZapParser] No vulnerabilities found in ZAP results");
    }

    return result;
}
