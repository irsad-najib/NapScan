"use client";

import React from "react";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";
import { ToolKey } from "@/services/api";

interface ToolCardProps {
    tool: ToolKey;
    data: ToolExecution;
    vulnerabilities: ScanVulnerability[];
    onClick: () => void;
}

export function ToolCard({ tool, data, vulnerabilities, onClick }: ToolCardProps) {
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

    const toolVulns = vulnerabilities.filter(v => v.tool === tool);

    // Get status color for border/indicator
    const getStatusColor = (status: string) => {
        switch (status) {
            case "completed": return "border-emerald-500 text-emerald-600";
            case "running": return "border-blue-500 text-blue-600";
            case "failed": return "border-red-500 text-red-600";
            case "awaiting_decision": return "border-amber-500 text-amber-600";
            default: return "border-slate-300 text-slate-400";
        }
    };

    const statusColor = getStatusColor(data.status);

    return (
        <div
            onClick={onClick}
            className={`
                group relative bg-white dark:bg-slate-900 
                rounded-xl border border-slate-200 dark:border-slate-800 
                p-6 h-40 flex flex-col justify-between 
                cursor-pointer transition-all duration-200 
                hover:shadow-lg hover:-translate-y-1 hover:border-slate-300 dark:hover:border-slate-700
                overflow-hidden
            `}
        >
            {/* Status Strip */}
            <div className={`absolute left-0 top-0 bottom-0 w-1 ${data.status === 'completed' ? 'bg-emerald-500' : data.status === 'running' ? 'bg-blue-500' : data.status === 'failed' ? 'bg-red-500' : 'bg-slate-300'}`} />

            <div className="flex justify-between items-start">
                <h3 className="font-bold text-lg text-slate-800 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                    {getToolName(tool)}
                </h3>

                {data.status === 'running' && (
                    <span className="animate-spin material-symbols-outlined text-blue-500 text-xl">
                        sync
                    </span>
                )}
                {data.status === 'completed' && (
                    <span className="material-symbols-outlined text-emerald-500 text-xl">
                        check_circle
                    </span>
                )}
                {data.status === 'failed' && (
                    <span className="material-symbols-outlined text-red-500 text-xl">
                        error
                    </span>
                )}
            </div>

            {/* Risk Dots */}
            <div className="flex items-center gap-2 mt-auto">
                {toolVulns.length > 0 ? (
                    <div className="flex items-center gap-1.5">
                        {toolVulns.filter(v => ['critical', 'high'].includes(v.severity.toLowerCase())).length > 0 &&
                            <span className="size-3 rounded-full bg-red-500 shadow-sm" title="Critical/High" />
                        }
                        {toolVulns.filter(v => ['medium'].includes(v.severity.toLowerCase())).length > 0 &&
                            <span className="size-3 rounded-full bg-amber-500 shadow-sm" title="Medium" />
                        }
                        {toolVulns.filter(v => ['low'].includes(v.severity.toLowerCase())).length > 0 &&
                            <span className="size-3 rounded-full bg-blue-500 shadow-sm" title="Low" />
                        }
                        <span className="text-xs font-bold text-slate-500 ml-1">
                            {toolVulns.length} Issues
                        </span>
                    </div>
                ) : (
                    <div className="flex items-center gap-2 text-slate-400 text-sm">
                        <span className="size-1.5 rounded-full bg-slate-300" />
                        <span className="text-xs">No issues</span>
                    </div>
                )}
            </div>

            {/* Hover visual cue */}
            <div className="absolute right-4 bottom-4 opacity-0 group-hover:opacity-100 transition-opacity">
                <span className="material-symbols-outlined text-slate-900 dark:text-white">
                    arrow_forward
                </span>
            </div>
        </div>
    );
}
