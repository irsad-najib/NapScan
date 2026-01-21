"use client";

import React, { useState, useMemo } from "react";
import { ScanVulnerability } from "@/context/ScanContext";
import { MobSFAppInfo } from "@/utils/toolParsers";

// Severity priority map (higher value = more severe)
const SEVERITY_ORDER: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};

type SortOrder = "desc" | "asc";

interface MobSFResultsViewProps {
    mobsfVulnerabilities: ScanVulnerability[];
    fridaVulnerabilities?: ScanVulnerability[];
    appInfo?: MobSFAppInfo | null;
    showFrida?: boolean;
}

export function MobSFResultsView({
    mobsfVulnerabilities,
    fridaVulnerabilities = [],
    appInfo,
    showFrida = false,
}: MobSFResultsViewProps) {
    const [activeSection, setActiveSection] = useState<"mobsf" | "frida">("mobsf");
    const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
    const [sortOrder, setSortOrder] = useState<SortOrder>("desc");

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

    const countBySeverity = (vulns: ScanVulnerability[]) => {
        return {
            critical: vulns.filter(v => v.severity.toLowerCase() === "critical").length,
            high: vulns.filter(v => v.severity.toLowerCase() === "high").length,
            medium: vulns.filter(v => v.severity.toLowerCase() === "medium").length,
            low: vulns.filter(v => v.severity.toLowerCase() === "low").length,
            info: vulns.filter(v => v.severity.toLowerCase() === "info").length,
        };
    };

    const mobsfCounts = countBySeverity(mobsfVulnerabilities);
    const fridaCounts = countBySeverity(fridaVulnerabilities);

    const currentVulns = activeSection === "mobsf" ? mobsfVulnerabilities : fridaVulnerabilities;

    // Sort vulnerabilities by severity
    const sortedVulns = useMemo(() => {
        return [...currentVulns].sort((a, b) => {
            const severityA = SEVERITY_ORDER[a.severity.toLowerCase()] || 0;
            const severityB = SEVERITY_ORDER[b.severity.toLowerCase()] || 0;
            return sortOrder === "desc" ? severityB - severityA : severityA - severityB;
        });
    }, [currentVulns, sortOrder]);

    return (
        <div className="space-y-6">
            {/* App Info Card */}
            {appInfo && (
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
                                <span className="text-[10px] text-slate-400">SCORE</span>
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
                        {mobsfVulnerabilities.length}
                    </span>
                </button>

                {showFrida && (
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
                            {fridaVulnerabilities.length}
                        </span>
                    </button>
                )}
            </div>

            {/* Severity Overview */}
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

            {/* Vulnerability List */}
            <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden">
                {/* Header with Sort Button */}
                <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between bg-slate-50 dark:bg-slate-800/50">
                    <h4 className="font-semibold text-slate-900 dark:text-white">
                        {activeSection === "mobsf" ? "Static Analysis Findings" : "Dynamic Analysis Findings"}
                    </h4>
                    <div className="flex items-center gap-3">
                        {/* Sort Button */}
                        <button
                            onClick={() => setSortOrder(sortOrder === "desc" ? "asc" : "desc")}
                            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
                            title={sortOrder === "desc" ? "Showing: Highest severity first" : "Showing: Lowest severity first"}
                        >
                            <span className="material-symbols-outlined text-sm">
                                {sortOrder === "desc" ? "arrow_downward" : "arrow_upward"}
                            </span>
                            <span>Severity {sortOrder === "desc" ? "↓" : "↑"}</span>
                        </button>
                        <span className="bg-slate-200 dark:bg-slate-600 text-slate-600 dark:text-slate-400 text-xs font-bold px-2 py-0.5 rounded-full">
                            {currentVulns.length} Issues
                        </span>
                    </div>
                </div>
                <div className="divide-y divide-slate-200 dark:divide-slate-700">
                    {sortedVulns.length === 0 ? (
                        <div className="p-12 text-center">
                            <span className="material-symbols-outlined text-5xl text-slate-300 dark:text-slate-600 mb-4">
                                check_circle
                            </span>
                            <p className="text-slate-500 dark:text-slate-400">
                                No findings in this section
                            </p>
                        </div>
                    ) : (
                        sortedVulns.map((vuln, idx) => (
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
        </div>
    );
}

export default MobSFResultsView;
