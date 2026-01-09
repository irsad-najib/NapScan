"use client";

import React from "react";
import { ToolKey } from "@/services/api";
import { ToolExecution } from "@/context/ScanContext";

interface ScanProgressProps {
    progress: number;
    status: string;
    tools: Record<ToolKey, ToolExecution>;
}

export function ScanProgress({ progress, status, tools }: ScanProgressProps) {
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

    const getStatusIcon = (status: string) => {
        switch (status) {
            case "completed":
                return <span className="material-symbols-outlined text-emerald-500">check_circle</span>;
            case "running":
                return <span className="material-symbols-outlined text-blue-500 animate-spin">sync</span>;
            case "failed":
                return <span className="material-symbols-outlined text-red-500">error</span>;
            default:
                return <span className="material-symbols-outlined text-slate-400">pending</span>;
        }
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case "completed":
                return "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30";
            case "running":
                return "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30";
            case "failed":
                return "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30";
            default:
                return "text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/30";
        }
    };

    return (
        <div className="flex flex-col gap-6">
            {/* Overall Progress */}
            <div className="bg-white dark:bg-slate-900 rounded-2xl p-6 border border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white">Scan Progress</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                            {status === "completed"
                                ? "All scanning tasks completed"
                                : "Scanning in progress..."}
                        </p>
                    </div>
                    <div className="text-right">
                        <span className="text-3xl font-bold text-slate-900 dark:text-white">{progress}%</span>
                    </div>
                </div>

                <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-4 overflow-hidden mb-2">
                    <div
                        className={`h-full rounded-full transition-all duration-500 ${status === "failed" ? "bg-red-500" : "bg-gradient-to-r from-blue-500 to-cyan-500 animate-pulse"
                            }`}
                        style={{ width: `${progress}%` }}
                    />
                </div>
            </div>

            {/* Tools Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(tools).map(([key, tool]) => (
                    <div
                        key={key}
                        className={`p-4 rounded-xl border flex flex-col gap-3 transition-all ${getStatusColor(tool.status)
                            }`}
                    >
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <span className="font-bold text-sm tracking-wide">{getToolName(key)}</span>
                            </div>
                            {getStatusIcon(tool.status)}
                        </div>

                        <div className="flex items-center gap-2 text-xs font-medium opacity-80">
                            <span className="capitalize">{tool.status}</span>
                            {tool.status === "running" && <span>• {tool.progress}%</span>}
                            {tool.startTime && tool.endTime && (
                                <span>• {Math.round((new Date(tool.endTime).getTime() - new Date(tool.startTime).getTime()) / 1000)}s</span>
                            )}
                        </div>

                        {tool.error && (
                            <div className="mt-1 p-2 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-xs rounded break-words font-mono">
                                {tool.error}
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}
