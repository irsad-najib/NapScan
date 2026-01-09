/**
 * Enhanced Nmap Result Parser
 * Converts raw Nmap API response into detailed vulnerability findings
 * Supports both processed API format and raw Nmap scan output
 */

import { ScanVulnerability } from "@/context/ScanContext";

// ============================================================================
// RAW NMAP SCAN OUTPUT INTERFACES
// Format: { tcp: { hosts: [...] }, udp: { hosts: [...] } }
// ============================================================================

export interface RawNmapAddress {
    addr: string;
}

export interface RawNmapService {
    name: string;
    product?: string;
    version?: string;
    extrainfo?: string;
}

export interface RawNmapState {
    state: "open" | "closed" | "filtered" | "open|filtered" | "unfiltered";
    reason?: string;
}

export interface RawNmapPort {
    port: string;
    protocol: "tcp" | "udp";
    State: RawNmapState;
    Service: RawNmapService;
}

export interface RawNmapPorts {
    ports: RawNmapPort[];
}

export interface RawNmapHost {
    addresses: RawNmapAddress[];
    ports: RawNmapPorts;
    hostnames?: { name: string }[];
    status?: { state: string };
}

export interface RawNmapProtocol {
    hosts: RawNmapHost[];
}

export interface RawNmapScanResult {
    tcp?: RawNmapProtocol;
    udp?: RawNmapProtocol;
}

export interface NmapRisk {
    _id: string;
    threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    target_id: string;
    title: string;
    created_at: string;
    last_detected_at: string;
}

export interface NmapApiResponse {
    type: string;
    state: string;
    requested_targets: Array<{ target: string; label: string }>;
    resolved_targets: Array<{ target: string; label: string; resolved_target: string }>;
    created_at: string;
    updated_at: string;
    progress: number;
    report_id: string;
    risks: {
        closed: NmapRisk[];
        new_open: NmapRisk[];
        still_open: NmapRisk[];
    };
    results?: Array<{ resultId: string; contentType: string }>;
}

export interface NmapVulnerability {
    id: string;
    name: string;
    title: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    description: string;
    impact: string;
    evidence: string;
    recommendation: string;
    affected_port: number;
    protocol: "tcp" | "udp";
    service: string;
    scanner: "nmap";
    confidence: "high" | "medium" | "low";
    status: "new" | "existing" | "closed";
    first_detected: string;
    last_detected: string;
    tool: "nmap";
}

/**
 * Map threat level to severity
 */
function mapThreatLevel(threat: string): "Critical" | "High" | "Medium" | "Low" | "Info" {
    switch (threat.toUpperCase()) {
        case "CRITICAL": return "Critical";
        case "HIGH": return "High";
        case "MEDIUM": return "Medium";
        case "LOW": return "Low";
        default: return "Info";
    }
}

/**
 * Extract port number from title like "Open TCP Port: 8080"
 */
function extractPort(title: string): number {
    const match = title.match(/Port:\s*(\d+)/);
    return match ? parseInt(match[1]) : 0;
}

/**
 * Extract protocol from title like "Open TCP Port: 8080"
 */
function extractProtocol(title: string): "tcp" | "udp" {
    if (title.toLowerCase().includes("udp")) return "udp";
    return "tcp";
}

/**
 * Get impact description based on port
 */
function getImpact(port: number): string {
    const impacts: Record<number, string> = {
        161: "Attackers can extract sensitive system information through SNMP enumeration.",
        69: "Unauthenticated file transfers allow attackers to read or write files.",
        1900: "UPnP vulnerabilities can be exploited for DDoS attacks.",
        500: "ISAKMP exposure may allow VPN traffic interception.",
        8080: "Exposed admin interfaces provide potential access to management functions.",
        8443: "SSL-enabled admin ports may expose management interfaces.",
        3389: "RDP exposure is a common target for ransomware attacks.",
        5900: "VNC services can be exploited for unauthorized remote access.",
        23: "Telnet transmits all data including credentials in plaintext.",
        21: "FTP credentials and data are transmitted unencrypted.",
        445: "SMB exposure is a primary vector for ransomware.",
        3306: "Direct database access can lead to data breaches.",
        5432: "PostgreSQL exposure allows potential data access.",
        27017: "MongoDB without authentication can result in data theft.",
        6379: "Redis exposure can lead to remote code execution.",
        80: "Unencrypted HTTP traffic can be intercepted.",
        443: "HTTPS misconfiguration may expose encrypted traffic.",
        53: "DNS services can be abused for DDoS amplification.",
        22: "SSH exposure increases attack surface for brute force.",
    };
    return impacts[port] || `Exposed service on port ${port} increases attack surface.`;
}

/**
 * Get recommendation based on port
 */
function getRecommendation(port: number): string {
    const recommendations: Record<number, string> = {
        161: "Disable SNMP or use SNMPv3 with strong authentication.",
        69: "Disable TFTP service. Use SFTP or SCP instead.",
        1900: "Disable UPnP on internet-facing devices.",
        500: "Ensure ISAKMP is properly configured with strong encryption.",
        8080: "Move admin interfaces behind VPN or restrict access.",
        8443: "Secure admin ports with certificate-based authentication.",
        3389: "Disable RDP or use VPN with MFA.",
        5900: "Disable VNC or use SSH tunneling.",
        23: "Replace Telnet with SSH immediately.",
        21: "Replace FTP with SFTP or FTPS.",
        445: "Restrict SMB to internal networks only.",
        3306: "Bind MySQL to localhost only.",
        5432: "Configure PostgreSQL to listen only on localhost.",
        27017: "Enable MongoDB authentication.",
        6379: "Enable Redis authentication.",
        80: "Implement HTTPS redirect and enable HSTS.",
        443: "Ensure TLS 1.2+ is enforced.",
        53: "Implement DNS rate limiting.",
        22: "Use key-based authentication.",
    };
    return recommendations[port] || `Review the necessity of this service and restrict access.`;
}

/**
 * Parse a single risk into a vulnerability finding
 */
function parseRisk(risk: NmapRisk, status: "new" | "existing" | "closed"): NmapVulnerability {
    const port = extractPort(risk.title);
    const protocol = extractProtocol(risk.title);
    const severity = mapThreatLevel(risk.threat_level);

    return {
        id: risk._id,
        name: risk.title,
        title: risk.title,
        severity,
        description: `${risk.title} - This port is publicly accessible and may pose a security risk.`,
        impact: getImpact(port),
        evidence: `Port ${port}/${protocol} detected as open`,
        recommendation: getRecommendation(port),
        affected_port: port,
        protocol,
        service: `${protocol}/${port}`,
        scanner: "nmap",
        confidence: "medium",
        status,
        first_detected: risk.created_at,
        last_detected: risk.last_detected_at,
        tool: "nmap",
    };
}

/**
 * Parse Nmap API response and extract vulnerability findings
 */
export function parseNmapResults(rawResult: any): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];

    console.log("[NmapParser] Raw result received:", rawResult);

    try {
        const risks = rawResult?.risks;

        console.log("[NmapParser] Risks object:", risks);

        if (!risks) {
            console.warn("[NmapParser] No risks object found in Nmap response");
            return [];
        }

        // Parse new_open risks
        if (Array.isArray(risks.new_open)) {
            risks.new_open.forEach((risk: NmapRisk) => {
                const vuln = parseRisk(risk, "new");
                vulnerabilities.push({
                    id: vuln.id,
                    name: vuln.name,
                    severity: vuln.severity,
                    description: vuln.description,
                    tool: "nmap",
                });
            });
        }

        // Parse still_open risks
        if (Array.isArray(risks.still_open)) {
            risks.still_open.forEach((risk: NmapRisk) => {
                const vuln = parseRisk(risk, "existing");
                vulnerabilities.push({
                    id: vuln.id,
                    name: vuln.name,
                    severity: vuln.severity,
                    description: vuln.description,
                    tool: "nmap",
                });
            });
        }

        // Parse closed risks (optional - might want to show these differently)
        if (Array.isArray(risks.closed)) {
            risks.closed.forEach((risk: NmapRisk) => {
                const vuln = parseRisk(risk, "closed");
                vulnerabilities.push({
                    id: vuln.id,
                    name: `[Closed] ${vuln.name}`,
                    severity: "Info" as const,
                    description: `${vuln.description} (No longer detected)`,
                    tool: "nmap",
                });
            });
        }

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Nmap results:", error);
        return [];
    }
}

/**
 * Get detailed findings with all fields
 */
export function parseNmapResultsDetailed(rawResult: any): NmapVulnerability[] {
    const vulnerabilities: NmapVulnerability[] = [];

    try {
        const risks = rawResult?.risks;

        if (!risks) {
            return [];
        }

        if (Array.isArray(risks.new_open)) {
            risks.new_open.forEach((risk: NmapRisk) => {
                vulnerabilities.push(parseRisk(risk, "new"));
            });
        }

        if (Array.isArray(risks.still_open)) {
            risks.still_open.forEach((risk: NmapRisk) => {
                vulnerabilities.push(parseRisk(risk, "existing"));
            });
        }

        return vulnerabilities;
    } catch (error) {
        console.error("Error parsing Nmap results:", error);
        return [];
    }
}

/**
 * Risk Summary
 */
export interface RiskSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    newCount: number;
    closedCount: number;
}

export function analyzeRisk(rawResult: any): RiskSummary {
    const summary: RiskSummary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        newCount: 0,
        closedCount: 0,
    };

    try {
        const risks = rawResult?.risks;
        if (!risks) return summary;

        const allOpen = [...(risks.new_open || []), ...(risks.still_open || [])];

        summary.newCount = risks.new_open?.length || 0;
        summary.closedCount = risks.closed?.length || 0;
        summary.total = allOpen.length;

        allOpen.forEach((risk: NmapRisk) => {
            const level = risk.threat_level?.toUpperCase();
            if (level === "CRITICAL") summary.critical++;
            else if (level === "HIGH") summary.high++;
            else if (level === "MEDIUM") summary.medium++;
            else if (level === "LOW") summary.low++;
        });

        return summary;
    } catch (error) {
        console.error("Error analyzing risk:", error);
        return summary;
    }
}

// ============================================================================
// RAW NMAP SCAN OUTPUT PARSER
// Parses format: { tcp: { hosts: [...] }, udp: { hosts: [...] } }
// ============================================================================

export interface ParsedNmapHost {
    ip: string;
    hostname?: string;
    ports: ParsedNmapPort[];
}

export interface ParsedNmapPort {
    port: number;
    protocol: "tcp" | "udp";
    state: string;
    service: string;
    product?: string;
    version?: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    impact: string;
    recommendation: string;
}

export interface ParsedNmapScanSummary {
    totalHosts: number;
    totalOpenPorts: number;
    totalFilteredPorts: number;
    tcpPorts: number;
    udpPorts: number;
    hosts: ParsedNmapHost[];
    severityCounts: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    services: { name: string; count: number; ports: number[] }[];
}

/**
 * Get severity level based on port and service
 */
function getPortSeverity(port: number, service: string, state: string): "Critical" | "High" | "Medium" | "Low" | "Info" {
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
}

/**
 * Get service display name
 */
function getServiceDisplayName(service: RawNmapService): string {
    let name = service.name || "unknown";
    if (service.product) {
        name += ` (${service.product}`;
        if (service.version) {
            name += ` ${service.version}`;
        }
        name += ")";
    }
    return name;
}

/**
 * Parse raw Nmap scan output
 */
export function parseRawNmapScan(rawResult: RawNmapScanResult): ParsedNmapScanSummary {
    const summary: ParsedNmapScanSummary = {
        totalHosts: 0,
        totalOpenPorts: 0,
        totalFilteredPorts: 0,
        tcpPorts: 0,
        udpPorts: 0,
        hosts: [],
        severityCounts: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        },
        services: [],
    };

    const serviceMap = new Map<string, { count: number; ports: number[] }>();

    // Process TCP hosts
    if (rawResult.tcp?.hosts) {
        rawResult.tcp.hosts.forEach(host => {
            const parsedHost = parseHost(host, "tcp", serviceMap, summary);
            if (parsedHost) {
                summary.hosts.push(parsedHost);
            }
        });
    }

    // Process UDP hosts
    if (rawResult.udp?.hosts) {
        rawResult.udp.hosts.forEach(host => {
            // Check if we already have this host from TCP
            const existingHost = summary.hosts.find(
                h => h.ip === host.addresses[0]?.addr
            );

            if (existingHost) {
                // Merge UDP ports into existing host
                const udpPorts = parseHostPorts(host, "udp", serviceMap, summary);
                existingHost.ports.push(...udpPorts);
            } else {
                const parsedHost = parseHost(host, "udp", serviceMap, summary);
                if (parsedHost) {
                    summary.hosts.push(parsedHost);
                }
            }
        });
    }

    summary.totalHosts = summary.hosts.length;

    // Convert service map to array
    summary.services = Array.from(serviceMap.entries())
        .map(([name, data]) => ({
            name,
            count: data.count,
            ports: data.ports,
        }))
        .sort((a, b) => b.count - a.count);

    return summary;
}

/**
 * Parse host ports
 */
function parseHostPorts(
    host: RawNmapHost,
    defaultProtocol: "tcp" | "udp",
    serviceMap: Map<string, { count: number; ports: number[] }>,
    summary: ParsedNmapScanSummary
): ParsedNmapPort[] {
    const ports: ParsedNmapPort[] = [];

    if (!host.ports?.ports) return ports;

    host.ports.ports.forEach(port => {
        const portNum = parseInt(port.port);
        const protocol = port.protocol || defaultProtocol;
        const state = port.State?.state || "unknown";
        const serviceName = port.Service?.name || "unknown";

        // Track open vs filtered
        if (state.includes("open")) {
            summary.totalOpenPorts++;
        }
        if (state.includes("filtered")) {
            summary.totalFilteredPorts++;
        }

        // Track by protocol
        if (protocol === "tcp") {
            summary.tcpPorts++;
        } else {
            summary.udpPorts++;
        }

        const severity = getPortSeverity(portNum, serviceName, state);

        // Update severity counts
        switch (severity) {
            case "Critical": summary.severityCounts.critical++; break;
            case "High": summary.severityCounts.high++; break;
            case "Medium": summary.severityCounts.medium++; break;
            case "Low": summary.severityCounts.low++; break;
            case "Info": summary.severityCounts.info++; break;
        }

        // Track services
        if (!serviceMap.has(serviceName)) {
            serviceMap.set(serviceName, { count: 0, ports: [] });
        }
        const serviceData = serviceMap.get(serviceName)!;
        serviceData.count++;
        if (!serviceData.ports.includes(portNum)) {
            serviceData.ports.push(portNum);
        }

        ports.push({
            port: portNum,
            protocol,
            state,
            service: serviceName,
            product: port.Service?.product,
            version: port.Service?.version,
            severity,
            impact: getImpact(portNum),
            recommendation: getRecommendation(portNum),
        });
    });

    return ports;
}

/**
 * Parse a single host
 */
function parseHost(
    host: RawNmapHost,
    defaultProtocol: "tcp" | "udp",
    serviceMap: Map<string, { count: number; ports: number[] }>,
    summary: ParsedNmapScanSummary
): ParsedNmapHost | null {
    const ip = host.addresses[0]?.addr;
    if (!ip) return null;

    const ports = parseHostPorts(host, defaultProtocol, serviceMap, summary);

    return {
        ip,
        hostname: host.hostnames?.[0]?.name,
        ports,
    };
}

/**
 * Convert raw Nmap scan to ScanVulnerability array for display
 */
export function parseRawNmapToVulnerabilities(rawResult: RawNmapScanResult): ScanVulnerability[] {
    const vulnerabilities: ScanVulnerability[] = [];
    const parsed = parseRawNmapScan(rawResult);

    parsed.hosts.forEach(host => {
        host.ports.forEach(port => {
            // Only include open ports or open|filtered as findings
            if (!port.state.includes("open")) return;

            vulnerabilities.push({
                id: `nmap-${host.ip}-${port.protocol}-${port.port}`,
                name: `Open ${port.protocol.toUpperCase()} Port: ${port.port} (${port.service})`,
                severity: port.severity,
                description: `Port ${port.port}/${port.protocol} is ${port.state} running ${port.service}. ${port.impact}`,
                tool: "nmap",
            });
        });
    });

    return vulnerabilities;
}

/**
 * Detect format and parse accordingly
 */
export function parseNmapAuto(rawResult: any): ScanVulnerability[] {
    // Check if it's raw Nmap format (has tcp or udp keys)
    if (rawResult?.tcp || rawResult?.udp) {
        console.log("[NmapParser] Detected raw Nmap format");
        return parseRawNmapToVulnerabilities(rawResult);
    }

    // Check if it's the processed API format (has risks key)
    if (rawResult?.risks) {
        console.log("[NmapParser] Detected API format with risks");
        return parseNmapResults(rawResult);
    }

    console.warn("[NmapParser] Unknown Nmap result format");
    return [];
}

