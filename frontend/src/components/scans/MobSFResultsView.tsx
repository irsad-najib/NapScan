"use client";

import React, { useState, useMemo } from "react";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";
import { ParsedResultTable } from "./ParsedResultTable";
import { getToolTableData, MobSFAppInfo, parseMobsfResults, parseFridaResults } from "@/utils/toolParsers";

// Severity priority map (higher value = more severe)
const SEVERITY_ORDER: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};


type SeverityFilter = "all" | "critical" | "high" | "medium" | "low" | "info";

interface MobSFResultsViewProps {
    toolData: ToolExecution;
    target: string;
    mobsfVulnerabilities: ScanVulnerability[];
    fridaVulnerabilities?: ScanVulnerability[];
    appInfo?: MobSFAppInfo | null;
    showFrida?: boolean;
}

export function MobSFResultsView({
    toolData,
    target,
    mobsfVulnerabilities,
    fridaVulnerabilities = [],
    appInfo,
    showFrida = false,
}: MobSFResultsViewProps) {
    const [activeSection, setActiveSection] = useState<"mobsf" | "frida">("mobsf");
    const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

    const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
    const [showRaw, setShowRaw] = useState(false);

    // DEBUG: Log incoming data
    console.log("[MobSFResultsView] toolData:", toolData);
    console.log("[MobSFResultsView] toolData.result:", toolData?.result);
    console.log("[MobSFResultsView] mobsfVulnerabilities:", mobsfVulnerabilities);
    console.log("[MobSFResultsView] fridaVulnerabilities:", fridaVulnerabilities);

    // Standard Metadata for the grid
    const metadata = [
        { label: "Scanner", value: toolData.tool.toUpperCase() },
        { label: "Target", value: target },
        { label: "Start Time", value: toolData.startTime ? new Date(toolData.startTime).toLocaleString() : "-" },
        { label: "End Time", value: toolData.endTime ? new Date(toolData.endTime).toLocaleString() : "-" },
        { label: "Status", value: toolData.status.toUpperCase() },
        {
            label: "Duration", value: toolData.startTime && toolData.endTime
                ? `${Math.round((new Date(toolData.endTime).getTime() - new Date(toolData.startTime).getTime()) / 1000)}s`
                : "-"
        },
    ];

    const getSeverityStyle = (severity: string) => {
        switch (severity.toLowerCase()) {
            case "critical":
                return "bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-500/30";
            case "high":
                return "bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-500/30";
            case "medium":
                return "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30";
            case "low":
                return "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30";
            default:
                return "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30";
        }
    };


    const getSeverityIcon = (severity: string) => {
        switch (severity.toLowerCase()) {
            case "critical":
            case "high":
                return "error";
            case "medium":
                return "warning";
            case "low":
                return "info";
            default:
                return "check_circle";
        }
    };

    // Fallback: Parse from toolData.result if props are empty
    const effectiveMobsfVulns = useMemo(() => {
        if (mobsfVulnerabilities.length > 0) {
            return mobsfVulnerabilities;
        }
        // Try to parse from toolData.result
        if (toolData?.result) {
            const parsed = parseMobsfResults(toolData.result);
            if (parsed.length > 0) {
                return parsed.filter(v => !v.tags?.includes('frida'));
            }
        }
        return [];
    }, [mobsfVulnerabilities, toolData]);

    const effectiveFridaVulns = useMemo(() => {
        if (fridaVulnerabilities.length > 0) {
            return fridaVulnerabilities;
        }
        // Try to parse from toolData.result for Frida
        if (toolData?.result) {
            const parsed = parseFridaResults(toolData.result);
            if (parsed.length > 0) {
                return parsed;
            }
        }
        return [];
    }, [fridaVulnerabilities, toolData]);

    const countBySeverity = (vulns: ScanVulnerability[]) => {
        return {
            critical: vulns.filter(v => v.severity.toLowerCase() === "critical").length,
            high: vulns.filter(v => v.severity.toLowerCase() === "high").length,
            medium: vulns.filter(v => v.severity.toLowerCase() === "medium").length,
            low: vulns.filter(v => v.severity.toLowerCase() === "low").length,
            info: vulns.filter(v => v.severity.toLowerCase() === "info").length,
        };
    };

    const mobsfCounts = countBySeverity(effectiveMobsfVulns);
    const fridaCounts = countBySeverity(effectiveFridaVulns);

    const currentVulns = activeSection === "mobsf" ? effectiveMobsfVulns : effectiveFridaVulns;

    // Filter vulnerabilities
    const filteredAndSortedVulns = useMemo(() => {
        let vulns = [...currentVulns];

        // Filter
        if (severityFilter !== "all") {
            vulns = vulns.filter(v => v.severity.toLowerCase() === severityFilter);
        }

        return vulns;
    }, [currentVulns, severityFilter]);

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            {/* Header with Raw/Table toggle (Matching ToolMetadata) */}
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
                <div>
                    <h4 className="font-bold text-slate-900 dark:text-white text-sm">Scan Results</h4>
                    <p className="text-xs text-slate-500">Metadata & Parsed Output</p>
                </div>
                <div className="flex items-center gap-3">
                    <div className="flex items-center bg-slate-100 dark:bg-slate-700 rounded-lg p-1 border border-slate-200 dark:border-slate-600">
                        <button
                            onClick={() => setShowRaw(false)}
                            className={`px-3 py-1 text-xs font-bold rounded-md transition-all ${!showRaw
                                ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm ring-1 ring-slate-900/5 dark:ring-white/10'
                                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'}`}
                        >
                            Table
                        </button>
                        <button
                            onClick={() => setShowRaw(true)}
                            className={`px-3 py-1 text-xs font-bold rounded-md transition-all ${showRaw
                                ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm ring-1 ring-slate-900/5 dark:ring-white/10'
                                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'}`}
                        >
                            Raw
                        </button>
                    </div>
                </div>
            </div>

            {/* Metadata Grid (Matching ToolMetadata) */}
            <div className="p-6 border-b border-slate-200 dark:border-slate-800">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {metadata.map((item) => (
                        <div key={item.label}>
                            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">{item.label}</p>
                            <p className="text-sm font-mono text-slate-900 dark:text-white font-medium truncate" title={item.value}>
                                {item.value}
                            </p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="p-6">
                {!showRaw ? (
                    <div className="space-y-6">
                        {/* Error State */}
                        {toolData.status === "failed" && (
                            <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4">
                                <div className="flex items-center gap-2 mb-2">
                                    <span className="material-symbols-outlined text-red-600 dark:text-red-400">
                                        error
                                    </span>
                                    <h5 className="font-bold text-red-900 dark:text-red-200">Scan Failed</h5>
                                </div>
                                <p className="text-sm text-red-800 dark:text-red-300 font-mono">
                                    {toolData.error || "Unknown error occurred during scan"}
                                </p>
                            </div>
                        )}

                        {/* App Info Card */}
                        {/* Only show if not failed and appInfo exists */}
                        {toolData.status !== "failed" && appInfo && (
                            <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-2xl p-6 border border-slate-700">
                                <div className="flex items-start gap-5">
                                    {/* App Icon */}
                                    <div className="w-16 h-16 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl flex items-center justify-center shrink-0 shadow-lg">
                                        <span className="text-3xl">📱</span>
                                    </div>

                                    {/* App Details */}
                                    <div className="flex-1 min-w-0">
                                        <h3 className="text-xl font-bold text-white mb-1">{appInfo.appName}</h3>
                                        <p className="text-sm font-mono text-slate-400 mb-2">{appInfo.packageName}</p>
                                        <div className="flex flex-wrap gap-2">
                                            <span className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded">
                                                v{appInfo.versionName}
                                            </span>
                                            <span className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded">
                                                SDK {appInfo.minSdk} - {appInfo.targetSdk}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Security Score */}
                                    <div className="text-center shrink-0">
                                        <div className={`w-16 h-16 rounded-full flex flex-col items-center justify-center ${parseInt(appInfo.securityScore) >= 70 ? 'bg-green-500/20 border-2 border-green-500' :
                                            parseInt(appInfo.securityScore) >= 50 ? 'bg-amber-500/20 border-2 border-amber-500' :
                                                'bg-red-500/20 border-2 border-red-500'
                                            }`}>
                                            <span className="text-xl font-bold text-white">{appInfo.securityScore}</span>
                                            <span className="text-xs text-slate-400">SCORE</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Stats Grid */}
                                <div className="grid grid-cols-4 gap-4 mt-6">
                                    <div className="bg-slate-700/50 rounded-xl p-3 text-center">
                                        <span className="block text-lg font-bold text-white">{appInfo.components.activities}</span>
                                        <span className="text-xs text-slate-400">Activities</span>
                                    </div>
                                    <div className="bg-slate-700/50 rounded-xl p-3 text-center">
                                        <span className="block text-lg font-bold text-white">{appInfo.permissions.dangerousCount}</span>
                                        <span className="text-xs text-slate-400">Dangerous Perms</span>
                                    </div>
                                    <div className="bg-slate-700/50 rounded-xl p-3 text-center">
                                        <span className="block text-lg font-bold text-white">{appInfo.network.domainsTotal}</span>
                                        <span className="text-xs text-slate-400">Domains</span>
                                    </div>
                                    <div className="bg-slate-700/50 rounded-xl p-3 text-center">
                                        <span className="block text-lg font-bold text-white">{appInfo.trackers.detected}</span>
                                        <span className="text-xs text-slate-400">Trackers</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Section Tabs */}
                        {toolData.status !== "failed" && (
                            <div className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 p-1 rounded-xl">
                                <button
                                    onClick={() => setActiveSection("mobsf")}
                                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-semibold text-sm transition-all ${activeSection === "mobsf"
                                        ? "bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm"
                                        : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                                        }`}
                                >
                                    <span className="material-symbols-outlined text-lg">security</span>
                                    <span>MobSF Static Analysis</span>
                                    <span className="bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-300 text-xs px-2 py-0.5 rounded-full">
                                        {effectiveMobsfVulns.length}
                                    </span>
                                </button>

                                {(showFrida || effectiveFridaVulns.length > 0) && (
                                    <button
                                        onClick={() => setActiveSection("frida")}
                                        className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-semibold text-sm transition-all ${activeSection === "frida"
                                            ? "bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm"
                                            : "text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
                                            }`}
                                    >
                                        <span className="material-symbols-outlined text-lg">bug_report</span>
                                        <span>Frida Dynamic Analysis</span>
                                        <span className="bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-300 text-xs px-2 py-0.5 rounded-full">
                                            {effectiveFridaVulns.length}
                                        </span>
                                    </button>
                                )}
                            </div>
                        )}

                        {/* Severity Overview */}
                        {toolData.status !== "failed" && (
                            <div className="flex items-center gap-3 p-4 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
                                <span className="text-sm font-semibold text-slate-600 dark:text-slate-400">Severity:</span>
                                <div className="flex items-center gap-4">
                                    {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).critical > 0 && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-3 h-3 rounded-full bg-red-500"></span>
                                            <span className="text-sm font-bold text-red-600 dark:text-red-400">
                                                {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).critical} Critical
                                            </span>
                                        </div>
                                    )}
                                    {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).high > 0 && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-3 h-3 rounded-full bg-orange-500"></span>
                                            <span className="text-sm font-bold text-orange-600 dark:text-orange-400">
                                                {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).high} High
                                            </span>
                                        </div>
                                    )}
                                    {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).medium > 0 && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-3 h-3 rounded-full bg-amber-500"></span>
                                            <span className="text-sm font-bold text-amber-600 dark:text-amber-400">
                                                {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).medium} Medium
                                            </span>
                                        </div>
                                    )}
                                    {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).low > 0 && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-3 h-3 rounded-full bg-blue-500"></span>
                                            <span className="text-sm font-bold text-blue-600 dark:text-blue-400">
                                                {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).low} Low
                                            </span>
                                        </div>
                                    )}
                                    {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).info > 0 && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-3 h-3 rounded-full bg-slate-400"></span>
                                            <span className="text-sm font-bold text-slate-600 dark:text-slate-400">
                                                {(activeSection === "mobsf" ? mobsfCounts : fridaCounts).info} Info
                                            </span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Vulnerability List / Filter / Empty State */}
                        {toolData.status !== "failed" && (
                            <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden">
                                {/* Header with Sort & Filter */}
                                <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between bg-slate-50 dark:bg-slate-800/50">
                                    <h4 className="font-semibold text-slate-900 dark:text-white">
                                        {activeSection === "mobsf" ? "Static Analysis Findings" : "Dynamic Analysis Findings"}
                                    </h4>
                                    <div className="flex items-center gap-3">
                                        {/* Severity Filter Dropdown */}
                                        <select
                                            value={severityFilter}
                                            onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
                                            className="text-xs font-semibold rounded-lg bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-600 px-2 py-1.5 outline-none focus:ring-2 focus:ring-blue-500"
                                        >
                                            <option value="all">All Severities</option>
                                            <option value="critical">Critical</option>
                                            <option value="high">High</option>
                                            <option value="medium">Medium</option>
                                            <option value="low">Low</option>
                                            <option value="info">Info</option>
                                        </select>

                                        {/* Sort Button */}

                                        <span className="bg-slate-200 dark:bg-slate-600 text-slate-600 dark:text-slate-400 text-xs font-bold px-2 py-0.5 rounded-full">
                                            {filteredAndSortedVulns.length} Issues
                                        </span>
                                    </div>
                                </div>
                                <div className="divide-y divide-slate-200 dark:divide-slate-700">
                                    {(toolData.status === 'running') && filteredAndSortedVulns.length === 0 ? (
                                        // Scan in Progress State
                                        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-50 to-white dark:from-slate-900 dark:to-slate-800 p-12 text-center border border-slate-200 dark:border-slate-800 group">
                                            {/* Background Decor */}
                                            <div className="absolute top-0 left-0 w-full h-full overflow-hidden opacity-50 pointer-events-none">
                                                <div className="absolute top-10 right-10 w-24 h-24 bg-blue-500/5 rounded-full blur-2xl animate-pulse"></div>
                                                <div className="absolute bottom-10 left-10 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl animate-pulse delay-700"></div>
                                            </div>

                                            {/* Icon wrapper with glow effect */}
                                            <div className="relative mx-auto w-24 h-24 mb-6">
                                                <div className="absolute inset-0 bg-blue-500/20 rounded-full blur-xl animate-pulse"></div>
                                                <div className="relative w-full h-full bg-gradient-to-br from-white to-blue-50 dark:from-slate-800 dark:to-slate-900 rounded-full flex items-center justify-center border-2 border-blue-100 dark:border-blue-900 shadow-xl">
                                                    <span className="material-symbols-outlined text-5xl text-blue-500 dark:text-blue-400 drop-shadow-sm animate-bounce-slow">
                                                        search
                                                    </span>
                                                </div>

                                                {/* Orbiting particles */}
                                                <div className="absolute inset-0 animate-spin-slow">
                                                    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-blue-400 rounded-full opacity-60"></div>
                                                    <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1.5 h-1.5 bg-cyan-400 rounded-full opacity-40"></div>
                                                </div>
                                            </div>

                                            {/* Text content */}
                                            <div className="relative z-10 space-y-3">
                                                <h3 className="text-2xl font-bold bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                                                    Scan in Progress
                                                </h3>
                                                <p className="text-slate-600 dark:text-slate-400 max-w-md mx-auto leading-relaxed text-base">
                                                    We are currently analyzing the target. Please wait while the scan completes.
                                                </p>
                                            </div>
                                        </div>
                                    ) : filteredAndSortedVulns.length === 0 ? (
                                        // All Clear / Empty State
                                        <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                                            <div className="w-16 h-16 bg-green-100 dark:bg-green-500/20 text-green-600 dark:text-green-400 rounded-full flex items-center justify-center mb-4">
                                                <span className="material-symbols-outlined text-3xl">check_circle</span>
                                            </div>
                                            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-1">
                                                {severityFilter === "all" ? "All Clear! No Issues Found" : "No Issues Found with this Filter"}
                                            </h3>
                                            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-sm">
                                                {severityFilter === "all"
                                                    ? "Great job! No vulnerabilities were detected in this section."
                                                    : `No ${severityFilter} severity vulnerabilities were found in this section.`}
                                            </p>
                                        </div>
                                    ) : (
                                        filteredAndSortedVulns.map((vuln, idx) => (
                                            <div
                                                key={vuln.id || idx}
                                                className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
                                            >
                                                <div
                                                    onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                                                    className="p-4 cursor-pointer"
                                                >
                                                    <div className="flex items-start gap-4">
                                                        {/* Severity Badge */}
                                                        <div className={`mt-0.5 shrink-0 px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border ${getSeverityStyle(vuln.severity)}`}>
                                                            <span className="material-symbols-outlined text-sm mr-1 align-middle">
                                                                {getSeverityIcon(vuln.severity)}
                                                            </span>
                                                            {vuln.severity}
                                                        </div>

                                                        {/* Content */}
                                                        <div className="flex-1 min-w-0">
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <h4 className="text-base font-semibold text-slate-900 dark:text-white">
                                                                    {vuln.name}
                                                                </h4>
                                                            </div>
                                                            <p className={`text-sm text-slate-600 dark:text-slate-400 ${expandedVuln === vuln.id ? '' : 'line-clamp-2'}`}>
                                                                {vuln.description}
                                                            </p>

                                                            {/* Extra details when expanded */}
                                                            {expandedVuln === vuln.id && (
                                                                <div className="mt-4 space-y-3">
                                                                    {vuln.affectedAsset && (
                                                                        <div className="flex items-center gap-2">
                                                                            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase">
                                                                                Affected:
                                                                            </span>
                                                                            <span className="text-sm text-slate-700 dark:text-slate-300 font-mono bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">
                                                                                {vuln.affectedAsset}
                                                                            </span>
                                                                        </div>
                                                                    )}
                                                                    {vuln.recommendation && (
                                                                        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                                                                            <span className="text-xs font-semibold text-blue-700 dark:text-blue-400 uppercase block mb-1">
                                                                                Recommendation:
                                                                            </span>
                                                                            <p className="text-sm text-blue-900 dark:text-blue-200">
                                                                                {vuln.recommendation}
                                                                            </p>
                                                                        </div>
                                                                    )}
                                                                    {/* Tags if any */}
                                                                    {vuln.tags && vuln.tags.length > 0 && (
                                                                        <div className="flex flex-wrap gap-2 mt-2">
                                                                            {vuln.tags.map(tag => (
                                                                                <span key={tag} className="text-xs font-mono bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-400 px-2 py-0.5 rounded">
                                                                                    #{tag}
                                                                                </span>
                                                                            ))}
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>

                                                        {/* Expand Icon */}
                                                        <span className={`material-symbols-outlined text-slate-400 transition-transform ${expandedVuln === vuln.id ? 'rotate-180' : ''}`}>
                                                            expand_more
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                ) : (
                    // Raw View (Matching ToolMetadata)
                    <div>
                        <div className="flex items-center justify-between mb-4">
                            <h5 className="font-bold text-slate-900 dark:text-white text-sm">Raw Output</h5>
                        </div>

                        {toolData.error ? (
                            <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4">
                                <div className="flex items-center gap-2 mb-2">
                                    <span className="material-symbols-outlined text-red-600 dark:text-red-400">
                                        error
                                    </span>
                                    <h5 className="font-bold text-red-900 dark:text-red-200">Error</h5>
                                </div>
                                <p className="text-sm text-red-800 dark:text-red-300 font-mono">
                                    {toolData.error}
                                </p>
                            </div>
                        ) : toolData.result ? (
                            <pre className="text-xs font-mono text-slate-900 dark:text-white bg-slate-50 dark:bg-slate-800/50 p-4 rounded-lg overflow-x-auto border border-slate-200 dark:border-slate-700 max-h-96 overflow-y-auto">
                                {JSON.stringify(toolData.result, null, 2)}
                            </pre>
                        ) : (
                            <div className="text-center py-8 text-slate-500">
                                <span className="material-symbols-outlined text-4xl mb-2 block opacity-50">
                                    pending
                                </span>
                                <p className="text-sm">No data available</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

export default MobSFResultsView;
