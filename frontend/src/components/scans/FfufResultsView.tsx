"use client";

import React, { useState, useMemo } from "react";

interface FfufResult {
    url: string;
    status: number;
    length: number;
    words: number;
    lines: number;
    duration: number;
    redirectlocation: string;
    host: string;
    input: {
        FUZZ: string;
        FFUFHASH: string;
    };
}

interface FfufResultsViewProps {
    rawData: any;
}

type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Info";

interface ParsedFfufResult extends FfufResult {
    severity: SeverityLevel;
    category: string;
}

export function FfufResultsView({ rawData }: FfufResultsViewProps) {
    const [filter, setFilter] = useState<SeverityLevel | "All">("All");
    const [searchTerm, setSearchTerm] = useState("");

    // Parse and categorize results
    const parsedResults = useMemo(() => {
        const data = rawData?.data || rawData;
        const results: FfufResult[] = data?.results || [];

        return results.map((result): ParsedFfufResult => {
            const path = result.input?.FUZZ || "";
            let severity: SeverityLevel = "Info";
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
            }
            // High: Admin & Config
            else if (/admin/i.test(path)) {
                severity = "High";
                category = "Admin Panel";
            } else if (/swagger|openapi/i.test(path)) {
                severity = "High";
                category = "API Documentation";
            } else if (/config\.(json|yml|yaml|xml)$/i.test(path)) {
                severity = "High";
                category = "Configuration";
            } else if (/composer|package.*\.json|docker/i.test(path)) {
                severity = "High";
                category = "Build/Deploy Config";
            }
            // Medium: Debug & Test
            else if (/debug|\.log$/i.test(path)) {
                severity = "Medium";
                category = "Debug/Logs";
            } else if (/test(s)?$|staging|dev$/i.test(path)) {
                severity = "Medium";
                category = "Test/Dev Endpoint";
            } else if (/api\/?$/i.test(path)) {
                severity = "Medium";
                category = "API Endpoint";
            }
            // Low: Common paths
            else if (/login|signin|auth|register|signup/i.test(path)) {
                severity = "Low";
                category = "Authentication";
            } else if (/static|assets|css|js|images/i.test(path)) {
                severity = "Low";
                category = "Static Resources";
            } else if (/dashboard|profile|settings/i.test(path)) {
                severity = "Low";
                category = "User Pages";
            }

            return { ...result, severity, category };
        });
    }, [rawData]);

    // Filter results
    const filteredResults = useMemo(() => {
        return parsedResults
            .filter(r => filter === "All" || r.severity === filter)
            .filter(r =>
                searchTerm === "" ||
                r.input.FUZZ.toLowerCase().includes(searchTerm.toLowerCase()) ||
                r.url.toLowerCase().includes(searchTerm.toLowerCase())
            )
            .sort((a, b) => {
                const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
                return order[a.severity] - order[b.severity];
            });
    }, [parsedResults, filter, searchTerm]);

    // Count by severity
    const severityCounts = useMemo(() => {
        const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
        parsedResults.forEach(r => counts[r.severity]++);
        return counts;
    }, [parsedResults]);

    const getSeverityColor = (severity: SeverityLevel) => {
        switch (severity) {
            case "Critical": return "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300 border-purple-200 dark:border-purple-800";
            case "High": return "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300 border-red-200 dark:border-red-800";
            case "Medium": return "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300 border-amber-200 dark:border-amber-800";
            case "Low": return "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300 border-blue-200 dark:border-blue-800";
            default: return "bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700";
        }
    };

    const getSeverityDot = (severity: SeverityLevel) => {
        switch (severity) {
            case "Critical": return "bg-purple-500";
            case "High": return "bg-red-500";
            case "Medium": return "bg-amber-500";
            case "Low": return "bg-blue-500";
            default: return "bg-slate-400";
        }
    };

    const getStatusColor = (status: number) => {
        if (status >= 200 && status < 300) return "text-emerald-600 dark:text-emerald-400";
        if (status >= 300 && status < 400) return "text-amber-600 dark:text-amber-400";
        if (status >= 400 && status < 500) return "text-red-600 dark:text-red-400";
        return "text-slate-600 dark:text-slate-400";
    };

    const config = rawData?.data?.config || rawData?.config;
    const scanTime = rawData?.data?.time || rawData?.time;

    return (
        <div className="space-y-6">
            {/* Summary Header */}
            <div className="bg-gradient-to-r from-slate-50 to-slate-100 dark:from-slate-800/50 dark:to-slate-900/50 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                            FFUF Directory/File Discovery
                        </h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                            {parsedResults.length} paths discovered
                            {scanTime && ` • ${new Date(scanTime).toLocaleString()}`}
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        {(["Critical", "High", "Medium", "Low", "Info"] as SeverityLevel[]).map(sev => (
                            severityCounts[sev] > 0 && (
                                <div key={sev} className={`px-2 py-1 rounded-full text-xs font-bold border ${getSeverityColor(sev)}`}>
                                    {severityCounts[sev]} {sev}
                                </div>
                            )
                        ))}
                    </div>
                </div>

                {/* Filters */}
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-slate-500">Filter:</span>
                        <select
                            value={filter}
                            onChange={(e) => setFilter(e.target.value as SeverityLevel | "All")}
                            className="text-xs px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                        >
                            <option value="All">All ({parsedResults.length})</option>
                            <option value="Critical">Critical ({severityCounts.Critical})</option>
                            <option value="High">High ({severityCounts.High})</option>
                            <option value="Medium">Medium ({severityCounts.Medium})</option>
                            <option value="Low">Low ({severityCounts.Low})</option>
                            <option value="Info">Info ({severityCounts.Info})</option>
                        </select>
                    </div>
                    <div className="flex-1">
                        <input
                            type="text"
                            placeholder="Search paths..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full text-xs px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white placeholder:text-slate-400"
                        />
                    </div>
                </div>
            </div>

            {/* Results Table */}
            <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                    <thead>
                        <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                            <th className="text-left px-4 py-3 font-semibold text-slate-700 dark:text-slate-300">Path</th>
                            <th className="text-left px-4 py-3 font-semibold text-slate-700 dark:text-slate-300 w-28">Category</th>
                            <th className="text-center px-4 py-3 font-semibold text-slate-700 dark:text-slate-300 w-20">Status</th>
                            <th className="text-right px-4 py-3 font-semibold text-slate-700 dark:text-slate-300 w-20">Size</th>
                            <th className="text-center px-4 py-3 font-semibold text-slate-700 dark:text-slate-300 w-24">Severity</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                        {filteredResults.map((result, idx) => (
                            <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                                <td className="px-4 py-3">
                                    <div className="flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${getSeverityDot(result.severity)}`} />
                                        <div className="min-w-0">
                                            <p className="font-mono text-xs text-slate-900 dark:text-white truncate">
                                                /{result.input.FUZZ}
                                            </p>
                                            {result.redirectlocation && result.redirectlocation !== "/" && (
                                                <p className="text-xs text-slate-500 truncate">
                                                    → {result.redirectlocation}
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                </td>
                                <td className="px-4 py-3">
                                    <span className="text-xs text-slate-600 dark:text-slate-400">
                                        {result.category}
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-center">
                                    <span className={`font-mono font-bold text-xs ${getStatusColor(result.status)}`}>
                                        {result.status}
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-right">
                                    <span className="font-mono text-xs text-slate-500">
                                        {result.length}B
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-center">
                                    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-bold border ${getSeverityColor(result.severity)}`}>
                                        {result.severity}
                                    </span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {filteredResults.length === 0 && (
                    <div className="text-center py-8 text-slate-500 dark:text-slate-400">
                        No results match your filter
                    </div>
                )}
            </div>

            {/* Scan Config (Collapsible) */}
            {config && (
                <details className="group">
                    <summary className="cursor-pointer text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white">
                        <span className="inline-flex items-center gap-2">
                            <span className="material-symbols-outlined text-sm group-open:rotate-90 transition-transform">
                                chevron_right
                            </span>
                            Scan Configuration
                        </span>
                    </summary>
                    <div className="mt-3 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg">
                        <pre className="text-xs font-mono text-slate-600 dark:text-slate-400 overflow-x-auto">
                            {JSON.stringify(config, null, 2)}
                        </pre>
                    </div>
                </details>
            )}
        </div>
    );
}
