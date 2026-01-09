"use client";

import React, { useState } from "react";
import { ToolExecution } from "@/context/ScanContext";

interface ToolMetadataProps {
    toolData: ToolExecution;
    target: string;
}

export function ToolMetadata({ toolData, target }: ToolMetadataProps) {
    const [showRaw, setShowRaw] = useState(true);

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

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
                <h4 className="font-bold text-slate-900 dark:text-white text-sm">Scan Metadata & Raw Data</h4>
                <button
                    onClick={() => setShowRaw(!showRaw)}
                    className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors px-3 py-1 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-500/10">
                    {showRaw ? "Show Summary" : "Show Raw JSON"}
                </button>
            </div>
            <div className="p-6">
                {!showRaw ? (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                        {metadata.map((item) => (
                            <div key={item.label}>
                                <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">{item.label}</p>
                                <p className="text-sm font-mono text-slate-900 dark:text-white font-medium">{item.value}</p>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div>
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
                                <span className="material-symbols-outlined text-4xl mb-2 block">
                                    pending
                                </span>
                                <p className="text-sm">No data available yet</p>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
