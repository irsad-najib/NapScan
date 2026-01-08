"use client";

import React, { useMemo, useState } from "react";
import { parseRawNmapScan, ParsedNmapScanSummary, ParsedNmapHost, ParsedNmapPort } from "@/utils/nmapParser";

interface NmapResultsViewProps {
    rawResult: any;
}

export function NmapResultsView({ rawResult }: NmapResultsViewProps) {
    const [expandedHost, setExpandedHost] = useState<string | null>(null);

    const parsed = useMemo(() => {
        if (!rawResult?.tcp && !rawResult?.udp) return null;
        return parseRawNmapScan(rawResult);
    }, [rawResult]);

    if (!parsed) {
        return (
            <div className="p-6 text-center text-slate-500 dark:text-slate-400">
                <span className="material-symbols-outlined text-4xl mb-2 block">info</span>
                <p>No Nmap scan data available or format not recognized.</p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <SummaryCard
                    icon="dns"
                    label="Hosts"
                    value={parsed.totalHosts}
                    color="blue"
                />
                <SummaryCard
                    icon="lan"
                    label="Open Ports"
                    value={parsed.totalOpenPorts}
                    color="green"
                />
                <SummaryCard
                    icon="filter_alt"
                    label="Filtered"
                    value={parsed.totalFilteredPorts}
                    color="amber"
                />
                <SummaryCard
                    icon="swap_horiz"
                    label="TCP / UDP"
                    value={`${parsed.tcpPorts} / ${parsed.udpPorts}`}
                    color="purple"
                />
            </div>

            {/* Severity Breakdown */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">
                    Severity Breakdown
                </h3>
                <div className="flex flex-wrap gap-3">
                    <SeverityBadge severity="Critical" count={parsed.severityCounts.critical} />
                    <SeverityBadge severity="High" count={parsed.severityCounts.high} />
                    <SeverityBadge severity="Medium" count={parsed.severityCounts.medium} />
                    <SeverityBadge severity="Low" count={parsed.severityCounts.low} />
                    <SeverityBadge severity="Info" count={parsed.severityCounts.info} />
                </div>
            </div>

            {/* Services Found */}
            {parsed.services.length > 0 && (
                <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6">
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">
                        Services Detected
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {parsed.services.map((service) => (
                            <span
                                key={service.name}
                                className="inline-flex items-center gap-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 rounded-full text-sm text-slate-700 dark:text-slate-300"
                            >
                                <span className="font-semibold">{service.name}</span>
                                <span className="text-xs text-slate-500 dark:text-slate-400">
                                    ({service.count}x)
                                </span>
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Hosts & Ports */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                <div className="p-6 border-b border-slate-200 dark:border-slate-800">
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                        Host Details
                    </h3>
                </div>
                <div className="divide-y divide-slate-200 dark:divide-slate-800">
                    {parsed.hosts.map((host) => (
                        <HostCard
                            key={host.ip}
                            host={host}
                            isExpanded={expandedHost === host.ip}
                            onToggle={() => setExpandedHost(expandedHost === host.ip ? null : host.ip)}
                        />
                    ))}
                </div>
            </div>
        </div>
    );
}

// Summary Card Component
function SummaryCard({
    icon,
    label,
    value,
    color,
}: {
    icon: string;
    label: string;
    value: string | number;
    color: "blue" | "green" | "amber" | "purple" | "red";
}) {
    const colorStyles = {
        blue: "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400",
        green: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
        amber: "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400",
        purple: "bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400",
        red: "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400",
    };

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
            <div className={`inline-flex p-2 rounded-lg mb-3 ${colorStyles[color]}`}>
                <span className="material-symbols-outlined text-xl">{icon}</span>
            </div>
            <div className="text-2xl font-bold text-slate-900 dark:text-white">{value}</div>
            <div className="text-sm text-slate-500 dark:text-slate-400">{label}</div>
        </div>
    );
}

// Severity Badge Component
function SeverityBadge({
    severity,
    count,
}: {
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    count: number;
}) {
    const styles: Record<string, string> = {
        Critical: "bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-500/30",
        High: "bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-500/30",
        Medium: "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30",
        Low: "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30",
        Info: "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30",
    };

    return (
        <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${styles[severity]}`}>
            <span className="font-semibold text-sm">{severity}</span>
            <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-white/50 dark:bg-black/20">
                {count}
            </span>
        </div>
    );
}

// Host Card Component
function HostCard({
    host,
    isExpanded,
    onToggle,
}: {
    host: ParsedNmapHost;
    isExpanded: boolean;
    onToggle: () => void;
}) {
    const criticalCount = host.ports.filter(p => p.severity === "Critical").length;
    const highCount = host.ports.filter(p => p.severity === "High").length;

    return (
        <div>
            <button
                onClick={onToggle}
                className="w-full p-4 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
            >
                <div className="flex items-center gap-4">
                    <div className="p-2 bg-slate-100 dark:bg-slate-800 rounded-lg">
                        <span className="material-symbols-outlined text-slate-600 dark:text-slate-400">
                            computer
                        </span>
                    </div>
                    <div className="text-left">
                        <div className="font-semibold text-slate-900 dark:text-white">
                            {host.ip}
                        </div>
                        {host.hostname && (
                            <div className="text-sm text-slate-500 dark:text-slate-400">
                                {host.hostname}
                            </div>
                        )}
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    {criticalCount > 0 && (
                        <span className="px-2 py-1 text-xs font-bold bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 rounded">
                            {criticalCount} Critical
                        </span>
                    )}
                    {highCount > 0 && (
                        <span className="px-2 py-1 text-xs font-bold bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300 rounded">
                            {highCount} High
                        </span>
                    )}
                    <span className="px-2 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 rounded">
                        {host.ports.length} ports
                    </span>
                    <span className={`material-symbols-outlined transition-transform ${isExpanded ? "rotate-180" : ""}`}>
                        expand_more
                    </span>
                </div>
            </button>

            {isExpanded && (
                <div className="px-4 pb-4">
                    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                        <table className="w-full text-sm">
                            <thead className="bg-slate-50 dark:bg-slate-800">
                                <tr>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300">Port</th>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300">Protocol</th>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300">State</th>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300">Service</th>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300">Severity</th>
                                    <th className="px-4 py-3 text-left font-semibold text-slate-700 dark:text-slate-300 hidden lg:table-cell">Recommendation</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                                {host.ports.map((port) => (
                                    <PortRow key={`${port.protocol}-${port.port}`} port={port} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}

// Port Row Component
function PortRow({ port }: { port: ParsedNmapPort }) {
    const severityStyles: Record<string, string> = {
        Critical: "bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300",
        High: "bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300",
        Medium: "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300",
        Low: "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300",
        Info: "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300",
    };

    const stateStyles: Record<string, string> = {
        open: "text-emerald-600 dark:text-emerald-400",
        "open|filtered": "text-amber-600 dark:text-amber-400",
        filtered: "text-slate-500 dark:text-slate-400",
        closed: "text-red-600 dark:text-red-400",
    };

    return (
        <tr className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
            <td className="px-4 py-3 font-mono font-semibold text-slate-900 dark:text-white">
                {port.port}
            </td>
            <td className="px-4 py-3">
                <span className="uppercase text-xs font-bold px-2 py-1 bg-slate-100 dark:bg-slate-800 rounded">
                    {port.protocol}
                </span>
            </td>
            <td className="px-4 py-3">
                <span className={`font-medium ${stateStyles[port.state] || "text-slate-600"}`}>
                    {port.state}
                </span>
            </td>
            <td className="px-4 py-3 text-slate-700 dark:text-slate-300">
                {port.service}
                {port.product && (
                    <span className="text-xs text-slate-500 dark:text-slate-400 ml-1">
                        ({port.product}{port.version ? ` ${port.version}` : ""})
                    </span>
                )}
            </td>
            <td className="px-4 py-3">
                <span className={`px-2 py-1 text-xs font-bold rounded ${severityStyles[port.severity]}`}>
                    {port.severity}
                </span>
            </td>
            <td className="px-4 py-3 text-slate-600 dark:text-slate-400 text-xs hidden lg:table-cell max-w-xs truncate" title={port.recommendation}>
                {port.recommendation}
            </td>
        </tr>
    );
}

export default NmapResultsView;
