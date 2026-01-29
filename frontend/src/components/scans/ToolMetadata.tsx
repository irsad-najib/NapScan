"use client";

import React, { useState, useMemo } from "react";
import { ToolExecution } from "@/context/ScanContext";
import { ParsedResultTable } from "./ParsedResultTable";
import { getToolTableData } from "@/utils/toolParsers";

interface ToolMetadataProps {
    toolData: ToolExecution;
    target: string;
}

export function ToolMetadata({ toolData, target }: ToolMetadataProps) {
    const [showRaw, setShowRaw] = useState(false);

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

    // Compute tabular data for the table view
    const tableData = useMemo(() => {
        if (!toolData.result) return [];
        return getToolTableData(toolData.tool, toolData.result);
    }, [toolData.tool, toolData.result]);

    const hasTableData = tableData.length > 0;

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
                <div>
                    <h4 className="font-bold text-slate-900 dark:text-white text-sm">Scan Results</h4>
                    <p className="text-xs text-slate-500">Metadata & Parsed Output</p>
                </div>
                <div className="flex items-center gap-3">
                    {toolData.result && (
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
                    )}
                </div>
            </div>

            {/* Metadata Grid */}
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
                    <div>
                        <div className="flex items-center justify-between mb-4">
                            <h5 className="font-bold text-slate-900 dark:text-white text-sm">
                                Parsed Findings
                                {tableData.length > 0 && (
                                    <span className="ml-2 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-2 py-0.5 rounded-full text-xs">
                                        {tableData.length}
                                    </span>
                                )}
                            </h5>
                        </div>
                        <ParsedResultTable tool={toolData.tool} data={tableData} status={toolData.status} />
                    </div>
                ) : (
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
