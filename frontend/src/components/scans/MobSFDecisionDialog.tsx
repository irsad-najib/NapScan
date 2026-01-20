"use client";

import React, { useState, useMemo } from "react";
import { MobSFPendingDecision, ScanVulnerability } from "@/context/ScanContext";
import { parseMobsfResults } from "@/utils/toolParsers";

interface MobSFDecisionDialogProps {
    pending: MobSFPendingDecision;
    onDecision: (decision: "STOP" | "CONTINUE") => void;
    isSubmitting?: boolean;
}

export function MobSFDecisionDialog({ pending, onDecision, isSubmitting = false }: MobSFDecisionDialogProps) {
    const [activeTab, setActiveTab] = useState<"summary" | "details">("summary");
    const [expandedSection, setExpandedSection] = useState<string | null>("high");

    // Parse vulnerabilities from mobsfResult
    const vulnerabilities = useMemo(() => {
        if (!pending.mobsfResult) return [];
        return parseMobsfResults(pending.mobsfResult);
    }, [pending.mobsfResult]);

    // Group vulnerabilities by severity
    const groupedVulns = useMemo(() => {
        const groups: Record<string, ScanVulnerability[]> = {
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: [],
        };
        vulnerabilities.forEach(v => {
            const sev = v.severity.toLowerCase();
            if (groups[sev]) {
                groups[sev].push(v);
            } else {
                groups.info.push(v);
            }
        });
        return groups;
    }, [vulnerabilities]);

    const getScoreLevel = (score: string): string => {
        const numScore = parseInt(score, 10);
        if (isNaN(numScore)) return "medium";
        if (numScore < 25) return "critical";
        if (numScore < 50) return "low";
        if (numScore < 75) return "medium";
        return "high";
    };

    const getScoreDescription = (score: string): string => {
        const numScore = parseInt(score, 10);
        if (isNaN(numScore)) return "Unable to determine security score.";
        if (numScore < 25) {
            return "Critical security issues detected. This app has severe vulnerabilities that should be addressed immediately.";
        }
        if (numScore < 50) {
            return "Multiple security concerns found. The app has significant issues that need attention.";
        }
        if (numScore < 75) {
            return "Moderate security posture. Some issues were found that should be reviewed.";
        }
        return "Good security posture. Few issues detected, but dynamic analysis may reveal more.";
    };

    const getScoreColor = (score: string) => {
        const level = getScoreLevel(score);
        switch (level) {
            case "critical": return "from-red-600 to-red-800";
            case "low": return "from-orange-500 to-orange-700";
            case "medium": return "from-yellow-500 to-yellow-700";
            case "high": return "from-green-500 to-green-700";
            default: return "from-slate-500 to-slate-700";
        }
    };

    const getSeverityStyle = (severity: string) => {
        switch (severity.toLowerCase()) {
            case "critical":
                return "bg-red-500/20 text-red-300 border-red-500/30";
            case "high":
                return "bg-orange-500/20 text-orange-300 border-orange-500/30";
            case "medium":
                return "bg-amber-500/20 text-amber-300 border-amber-500/30";
            case "low":
                return "bg-blue-500/20 text-blue-300 border-blue-500/30";
            default:
                return "bg-slate-500/20 text-slate-300 border-slate-500/30";
        }
    };

    const severityLabels: Record<string, { label: string; icon: string; color: string }> = {
        critical: { label: "Critical", icon: "error", color: "text-red-400" },
        high: { label: "High", icon: "warning", color: "text-orange-400" },
        medium: { label: "Medium", icon: "info", color: "text-amber-400" },
        low: { label: "Low", icon: "check_circle", color: "text-blue-400" },
        info: { label: "Info", icon: "info", color: "text-slate-400" },
    };

    return (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[1000] p-5">
            <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-white/10 rounded-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden shadow-2xl flex flex-col">
                {/* Header */}
                <div className="p-6 border-b border-white/10">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center">
                            <span className="material-symbols-outlined text-white text-2xl">security</span>
                        </div>
                        <div className="flex-1">
                            <h2 className="text-xl font-semibold text-white m-0">MobSF Analysis Complete</h2>
                            <p className="text-white/60 text-sm mt-1">Review findings and decide how to proceed</p>
                        </div>
                        <div className={`w-16 h-16 rounded-full bg-gradient-to-br ${getScoreColor(pending.securityScore)} flex flex-col items-center justify-center`}>
                            <span className="text-xl font-bold text-white">{pending.securityScore}</span>
                            <span className="text-[9px] text-white/80">SCORE</span>
                        </div>
                    </div>

                    {/* App Info */}
                    <div className="flex items-center gap-3 mt-4 bg-white/5 p-3 rounded-xl">
                        <span className="text-2xl">📱</span>
                        <div className="flex-1 min-w-0">
                            <h3 className="text-white font-semibold text-sm truncate">{pending.appName}</h3>
                            <p className="text-white/50 text-xs font-mono truncate">{pending.packageName}</p>
                        </div>
                        <span className="text-white/40 text-xs truncate max-w-[150px]">{pending.fileName}</span>
                    </div>
                </div>

                {/* Tab Buttons */}
                <div className="flex border-b border-white/10">
                    <button
                        onClick={() => setActiveTab("summary")}
                        className={`flex-1 py-3 text-sm font-semibold transition-all ${activeTab === "summary"
                                ? "text-white border-b-2 border-indigo-500"
                                : "text-white/50 hover:text-white/80"
                            }`}
                    >
                        Summary
                    </button>
                    <button
                        onClick={() => setActiveTab("details")}
                        className={`flex-1 py-3 text-sm font-semibold transition-all flex items-center justify-center gap-2 ${activeTab === "details"
                                ? "text-white border-b-2 border-indigo-500"
                                : "text-white/50 hover:text-white/80"
                            }`}
                    >
                        Vulnerability Details
                        <span className="bg-white/10 text-xs px-2 py-0.5 rounded-full">{vulnerabilities.length}</span>
                    </button>
                </div>

                {/* Content Area - Scrollable */}
                <div className="flex-1 overflow-y-auto p-6">
                    {activeTab === "summary" ? (
                        <div className="space-y-6">
                            {/* Score Description */}
                            <p className="text-white/70 text-sm leading-relaxed">
                                {getScoreDescription(pending.securityScore)}
                            </p>

                            {/* Severity Breakdown */}
                            <div>
                                <h4 className="text-white/80 text-sm font-medium mb-3">Findings Summary</h4>
                                <div className="grid grid-cols-5 gap-2">
                                    {Object.entries(severityLabels).map(([key, { label, color }]) => (
                                        <div key={key} className={`bg-white/5 rounded-lg p-3 text-center ${groupedVulns[key]?.length > 0 ? '' : 'opacity-40'}`}>
                                            <span className={`block text-2xl font-bold ${color}`}>
                                                {groupedVulns[key]?.length || 0}
                                            </span>
                                            <span className="text-[10px] text-white/60 uppercase tracking-wide">{label}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Top Issues Preview */}
                            {(groupedVulns.critical.length > 0 || groupedVulns.high.length > 0) && (
                                <div>
                                    <h4 className="text-white/80 text-sm font-medium mb-3">Top Issues</h4>
                                    <div className="space-y-2">
                                        {[...groupedVulns.critical, ...groupedVulns.high].slice(0, 3).map((vuln, idx) => (
                                            <div key={idx} className="flex items-start gap-3 bg-white/5 p-3 rounded-lg">
                                                <span className={`material-symbols-outlined text-lg ${vuln.severity.toLowerCase() === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>
                                                    {vuln.severity.toLowerCase() === 'critical' ? 'error' : 'warning'}
                                                </span>
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-white text-sm font-medium truncate">{vuln.name}</p>
                                                    <p className="text-white/50 text-xs truncate">{vuln.description}</p>
                                                </div>
                                            </div>
                                        ))}
                                        {(groupedVulns.critical.length + groupedVulns.high.length) > 3 && (
                                            <button
                                                onClick={() => setActiveTab("details")}
                                                className="text-indigo-400 text-xs hover:text-indigo-300 transition-colors"
                                            >
                                                View all {groupedVulns.critical.length + groupedVulns.high.length} critical/high issues →
                                            </button>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* Frida Section */}
                            <div className="flex gap-4 bg-indigo-500/10 border border-indigo-500/30 p-4 rounded-xl">
                                <div className="text-3xl">🔬</div>
                                <div>
                                    <h4 className="text-white font-medium m-0 mb-2">Continue with Dynamic Analysis?</h4>
                                    <p className="text-white/60 text-sm m-0 leading-relaxed">
                                        Frida will perform runtime analysis to detect issues that static analysis cannot find,
                                        such as insecure data storage, SSL pinning bypass, and API security.
                                    </p>
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {Object.entries(severityLabels).map(([key, { label, icon, color }]) => {
                                const vulns = groupedVulns[key] || [];
                                if (vulns.length === 0) return null;

                                return (
                                    <div key={key} className="border border-white/10 rounded-xl overflow-hidden">
                                        <button
                                            onClick={() => setExpandedSection(expandedSection === key ? null : key)}
                                            className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
                                        >
                                            <div className="flex items-center gap-3">
                                                <span className={`material-symbols-outlined ${color}`}>{icon}</span>
                                                <span className="text-white font-medium">{label}</span>
                                                <span className="bg-white/10 text-white/60 text-xs px-2 py-0.5 rounded-full">
                                                    {vulns.length}
                                                </span>
                                            </div>
                                            <span className={`material-symbols-outlined text-white/40 transition-transform ${expandedSection === key ? 'rotate-180' : ''}`}>
                                                expand_more
                                            </span>
                                        </button>

                                        {expandedSection === key && (
                                            <div className="border-t border-white/10 max-h-[250px] overflow-y-auto">
                                                {vulns.map((vuln, idx) => (
                                                    <div key={idx} className="p-4 border-b border-white/5 last:border-b-0 hover:bg-white/5">
                                                        <div className="flex items-start gap-3">
                                                            <span className={`shrink-0 px-2 py-1 rounded text-[10px] font-bold uppercase border ${getSeverityStyle(vuln.severity)}`}>
                                                                {vuln.severity}
                                                            </span>
                                                            <div className="flex-1 min-w-0">
                                                                <p className="text-white text-sm font-medium mb-1">{vuln.name}</p>
                                                                <p className="text-white/50 text-xs leading-relaxed">{vuln.description}</p>
                                                                {vuln.affectedAsset && (
                                                                    <p className="text-white/30 text-xs mt-2 font-mono">
                                                                        📍 {vuln.affectedAsset}
                                                                    </p>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Action Buttons - Fixed at bottom */}
                <div className="p-6 border-t border-white/10 bg-slate-900/50">
                    <div className="grid grid-cols-2 gap-3">
                        <button
                            onClick={() => onDecision("STOP")}
                            disabled={isSubmitting}
                            className="flex flex-col items-center gap-1 p-4 rounded-xl font-semibold bg-white/10 hover:bg-white/15 text-white border border-white/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <span>{isSubmitting ? "Processing..." : "Stop Here"}</span>
                            <span className="text-xs font-normal text-white/70">Save MobSF results only</span>
                        </button>
                        <button
                            onClick={() => onDecision("CONTINUE")}
                            disabled={isSubmitting}
                            className="flex flex-col items-center gap-1 p-4 rounded-xl font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white transition-all hover:-translate-y-0.5 hover:shadow-lg hover:shadow-indigo-500/40 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <span>{isSubmitting ? "Processing..." : "Continue with Frida"}</span>
                            <span className="text-xs font-normal text-white/80">Run dynamic analysis</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default MobSFDecisionDialog;

