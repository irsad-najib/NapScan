"use client";

import React, { useState } from "react";
import { ToolKey } from "@/services/api";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";
import { ToolRiskOverview } from "./ToolRiskOverview";
import { ToolMetadata } from "./ToolMetadata";
import { VulnerabilityList } from "./VulnerabilityList";

interface ToolRowProps {
    tool: ToolKey;
    data: ToolExecution;
    target: string;
    vulnerabilities: ScanVulnerability[];
}

export function ToolRow({ tool, data, target, vulnerabilities }: ToolRowProps) {
    const [isExpanded, setIsExpanded] = useState(false);
    const [activeTab, setActiveTab] = useState<"vulns" | "metadata">("vulns");

    const getToolName = (key: string) => {
        const names: Record<string, string> = {
            nmap: "Nmap",
            zap: "OWASP ZAP",
            openvas: "OpenVAS",
            nuclei: "Nuclei",
            sslyze: "SSLyze",
            ffuf: "Ffuf",
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
            default:
                return "text-slate-600 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/30";
        }
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case "completed": return "check_circle";
            case "running": return "sync";
            case "failed": return "error";
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
                        <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded w-fit">
                            Lite
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
                        <span className="capitalize">{data.status}</span>
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
                        <span className="opacity-50">-</span>
                    )}
                </div>

                {/* Actions Kebab */}
                <div className="w-10 flex justify-center">
                    <button className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                        <span className="material-symbols-outlined">more_horiz</span>
                    </button>
                </div>
            </div>

            {/* Expanded Details */}
            {isExpanded && (
                <div className="border-t border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/50 p-6 animate-fade-in">
                    {/* Visual Overview */}
                    <div className="mb-6">
                        <ToolRiskOverview vulnerabilities={toolVulns} />
                    </div>

                    {/* Tabs for Details */}
                    <div>
                        <div className="flex items-center gap-6 border-b border-slate-200 dark:border-slate-800 mb-6">
                            <button
                                onClick={() => setActiveTab('vulns')}
                                className={`pb-3 text-sm font-semibold border-b-2 transition-all ${activeTab === 'vulns'
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                    }`}
                            >
                                Vulnerabilities
                                {vulnCount > 0 && (
                                    <span className="ml-2 bg-slate-200 dark:bg-slate-800 px-2 py-0.5 rounded-full text-xs">
                                        {vulnCount}
                                    </span>
                                )}
                            </button>
                            <button
                                onClick={() => setActiveTab('metadata')}
                                className={`pb-3 text-sm font-semibold border-b-2 transition-all ${activeTab === 'metadata'
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                                    }`}
                            >
                                Metadata & Raw Data
                            </button>
                        </div>

                        {/* Tab Content */}
                        <div>
                            {activeTab === 'vulns' && (
                                <VulnerabilityList vulnerabilities={toolVulns} />
                            )}
                            {activeTab === 'metadata' && (
                                <ToolMetadata toolData={data} target={target} />
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
