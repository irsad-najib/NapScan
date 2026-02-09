"use client";

import React, { useState, useMemo } from "react";
import { ToolKey } from "@/services/api";
import { ToolExecution, ScanVulnerability, useScan } from "@/context/ScanContext";
import { ToolRiskOverview } from "./ToolRiskOverview";
import { ToolMetadata } from "./ToolMetadata";
import { parseFridaResults, extractMobsfAppInfo, getToolTableData, parseMobsfResults } from "@/utils/toolParsers";
import { ParsedResultTable } from "./ParsedResultTable";
import { MobSFResultsView } from "./MobSFResultsView";

interface ToolRowProps {
    tool: ToolKey;
    data: ToolExecution;
    target: string;
    vulnerabilities: ScanVulnerability[];
    scanId?: string;
    // For MobSF: pass the full scan result to extract Frida findings
    fullScanResult?: any;
}

export function ToolRow({ tool, data, target, vulnerabilities, scanId, fullScanResult }: ToolRowProps) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [isSubmittingDecision, setIsSubmittingDecision] = useState(false);
    const [mobsfFridaView, setMobsfFridaView] = useState<"mobsf" | "frida">("mobsf");

    const { pendingDecisions, submitMobSFDecision, stopTool } = useScan();

    // Check if this tool has a pending decision
    const showDecisionUI = data.status === "awaiting_decision" && tool === "mobsf";

    // Check if this tool supports stop functionality
    const canStop = data.status === 'running' && ['nmap', 'ffuf', 'sslyze', 'zap'].includes(tool) && data.taskId;
    const [isStopping, setIsStopping] = useState(false);

    const handleStop = async () => {
        if (!scanId || !canStop) return;
        setIsStopping(true);
        try {
            await stopTool(scanId, tool);
        } finally {
            setIsStopping(false);
        }
    };

    const handleDecision = async (decision: "STOP" | "CONTINUE") => {
        if (!scanId) return;
        setIsSubmittingDecision(true);
        try {
            await submitMobSFDecision(scanId, decision);
        } finally {
            setIsSubmittingDecision(false);
        }
    };

    const getToolName = (key: string) => {
        const names: Record<string, string> = {
            nmap: "Nmap",
            zap: "OWASP ZAP",
            openvas: "OpenVAS",
            nuclei: "Nuclei",
            sslyze: "SSLyze",
            ffuf: "Ffuf",
            mobsf: "MobSF",
            frida: "Frida",
        };
        return names[key] || key;
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case "completed":
                return "text-emerald-600 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30";
            case "running":
                return "text-blue-600 bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30";
            case "failed":
                return "text-red-600 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30";
            case "awaiting_decision":
                return "text-amber-600 bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30";
            default:
                return "text-slate-600 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/30";
        }
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case "completed": return "check_circle";
            case "running": return "sync";
            case "failed": return "error";
            case "awaiting_decision": return "hourglass_top";
            default: return "pending";
        }
    };

    // Filter vulns specifically for this tool
    const toolVulns = vulnerabilities.filter(v => v.tool === tool);
    const vulnCount = toolVulns.length;

    return (
        <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden transition-all duration-200 hover:shadow-md">
            {/* Row Header - Clickable */}
            <div
                onClick={() => setIsExpanded(!isExpanded)}
                className="flex items-center p-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
            >
                <div className="w-10 flex justify-center text-slate-400">
                    <span className={`material-symbols-outlined transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                        expand_more
                    </span>
                </div>

                {/* Tool Name */}
                <div className="w-48 flex items-center gap-3">
                    <div className="size-8 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center font-bold text-xs uppercase tracking-tight text-slate-700 dark:text-slate-300">
                        {tool.substring(0, 2)}
                    </div>
                    <div className="flex flex-col">
                        <span className="font-bold text-slate-900 dark:text-white text-sm">
                            {getToolName(tool)}
                        </span>
                    </div>
                </div>

                {/* Target */}
                <div className="flex-1 px-4">
                    <span className="text-sm font-mono text-slate-600 dark:text-slate-400">
                        {target}
                    </span>
                    <p className="text-xs text-slate-400">Target</p>
                </div>

                {/* Status */}
                <div className="w-32 flex items-center gap-2">
                    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${getStatusColor(data.status)}`}>
                        <span className={`material-symbols-outlined text-sm ${data.status === 'running' ? 'animate-spin' : ''}`}>
                            {getStatusIcon(data.status)}
                        </span>
                        <span className="capitalize">
                            {data.status === 'running' && ['openvas', 'nmap', 'nuclei', 'ffuf', 'sslyze', 'zap'].includes(data.tool) && data.progress !== undefined
                                ? `${data.progress}%`
                                : data.status}
                        </span>
                    </div>
                </div>

                {/* Duration */}
                <div className="w-24 text-right px-4">
                    <span className="text-xs font-mono font-medium text-slate-500 dark:text-slate-400">
                        {data.startTime && data.endTime
                            ? `${Math.round((new Date(data.endTime).getTime() - new Date(data.startTime).getTime()) / 1000)}s`
                            : data.status === 'running'
                                ? '...'
                                : '-'}
                    </span>
                </div>

                {/* Stop Button */}
                {canStop && (
                    <div className="w-20 flex items-center justify-center">
                        <button
                            onClick={(e) => {
                                e.stopPropagation();
                                handleStop();
                            }}
                            disabled={isStopping}
                            className="flex items-center gap-1 px-2 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 dark:hover:bg-red-500/20 border border-red-200 dark:border-red-500/30 rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            title="Stop this scan"
                        >
                            <span className={`material-symbols-outlined text-sm ${isStopping ? 'animate-spin' : ''}`}>
                                {isStopping ? 'sync' : 'stop_circle'}
                            </span>
                            <span>{isStopping ? 'Stopping' : 'Stop'}</span>
                        </button>
                    </div>
                )}

                {/* Risks Mini Summary (Dots) */}
                <div className="w-32 flex items-center justify-end gap-1.5 px-4 text-xs font-mono text-slate-400">
                    {toolVulns.length > 0 ? (
                        <>
                            {toolVulns.filter(v => ['critical', 'high'].includes(v.severity.toLowerCase())).length > 0 &&
                                <span className="size-2 rounded-full bg-red-500" title="Critical/High" />
                            }
                            {toolVulns.filter(v => ['medium'].includes(v.severity.toLowerCase())).length > 0 &&
                                <span className="size-2 rounded-full bg-amber-500" title="Medium" />
                            }
                            {toolVulns.filter(v => ['low'].includes(v.severity.toLowerCase())).length > 0 &&
                                <span className="size-2 rounded-full bg-blue-500" title="Low" />
                            }
                            <span className="ml-1 font-bold text-slate-600 dark:text-slate-300">{toolVulns.length}</span>
                        </>
                    ) : (
                        data.status === 'completed' ? (
                            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-50 dark:bg-emerald-500/10 rounded border border-emerald-100 dark:border-emerald-500/20">
                                <span className="material-symbols-outlined text-[14px] text-emerald-500">check_circle</span>
                                <span className="text-[10px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide">Clean</span>
                            </div>
                        ) : (
                            <span className="opacity-50">-</span>
                        )
                    )}
                </div>

                {/* Actions Kebab */}
                <div className="w-10 flex justify-center">
                    <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                        <span className="material-symbols-outlined">more_horiz</span>
                    </button>
                </div>
            </div>

            {/* Decision UI for awaiting_decision status */}
            {showDecisionUI && (
                <div className="border-t border-amber-200 dark:border-amber-500/30 bg-gradient-to-r from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20 p-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <span className="material-symbols-outlined text-amber-600 dark:text-amber-400 text-2xl">
                                help
                            </span>
                            <div>
                                <p className="font-bold text-slate-900 dark:text-white text-sm">
                                    MobSF Analysis Complete - Action Required
                                </p>
                                <p className="text-xs text-slate-600 dark:text-slate-400">
                                    Choose to stop here or continue with Frida dynamic analysis
                                </p>
                            </div>
                        </div>
                        <div className="flex items-center gap-3">
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    handleDecision("STOP");
                                }}
                                disabled={isSubmittingDecision}
                                className="flex items-center gap-2 px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-lg font-semibold text-sm transition-all disabled:opacity-50"
                            >
                                <span className="material-symbols-outlined text-lg">stop_circle</span>
                                {isSubmittingDecision ? "Processing..." : "Stop Here"}
                            </button>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    handleDecision("CONTINUE");
                                }}
                                disabled={isSubmittingDecision}
                                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-lg font-semibold text-sm shadow-lg shadow-purple-500/30 transition-all disabled:opacity-50"
                            >
                                <span className="material-symbols-outlined text-lg">play_arrow</span>
                                {isSubmittingDecision ? "Processing..." : "Continue with Frida"}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Expanded Details */}
            {isExpanded && (
                <div className="border-t border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/50 p-6 animate-fade-in space-y-6">
                    {/* Visual Overview - Only show if there are risks and NOT using a custom view like MobSF */}
                    {toolVulns.length > 0 && tool.toLowerCase() !== 'mobsf' && (
                        <ToolRiskOverview vulnerabilities={toolVulns} />
                    )}

                    {/* Tool Specific Views or Generic Metadata Table */}
                    {tool.toLowerCase() === 'mobsf' ? (() => {
                        // Parse MobSF results, fallback to toolVulns if parsing returns empty
                        const parsedMobsf = data.result ? parseMobsfResults(data.result) : [];
                        const parsedFrida = data.result ? parseFridaResults(data.result) : [];

                        const mobsfVulns = parsedMobsf.filter(v => !v.tags?.includes('frida'));
                        const fridaVulns = parsedFrida;

                        // Use parsed results if available, otherwise fallback to pre-computed toolVulns
                        const finalMobsfVulns = mobsfVulns.length > 0
                            ? mobsfVulns
                            : toolVulns.filter(v => !v.tags?.includes('frida'));
                        const finalFridaVulns = fridaVulns.length > 0
                            ? fridaVulns
                            : toolVulns.filter(v => v.tags?.includes('frida'));

                        return (
                            <MobSFResultsView
                                toolData={data}
                                target={target}
                                mobsfVulnerabilities={finalMobsfVulns}
                                fridaVulnerabilities={finalFridaVulns}
                                appInfo={extractMobsfAppInfo(data.result)}
                                showFrida={true}
                            />
                        );
                    })() : (
                        <ToolMetadata
                            toolData={data}
                            target={target}
                            vulnerabilities={toolVulns}
                        />
                    )}
                </div>
            )}
        </div>
    );
}

