"use client";

import React, { useState } from "react";
import { ToolExecution } from "@/context/ScanContext";

interface ToolResultsProps {
    toolData: ToolExecution;
}

export function ToolResults({ toolData }: ToolResultsProps) {
    const [showRaw, setShowRaw] = useState(false);

    // If there's an error, show it prominently
    if (toolData.status === "failed" && toolData.error) {
        return (
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-red-200 dark:border-red-800 overflow-hidden shadow-sm">
                <div className="p-4 border-b border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20">
                    <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-red-600 dark:text-red-400">
                            error
                        </span>
                        <h4 className="font-bold text-red-900 dark:text-red-200 text-sm">
                            Scan Failed
                        </h4>
                    </div>
                </div>
                <div className="p-6">
                    <p className="text-sm text-red-800 dark:text-red-300 font-mono bg-red-50 dark:bg-red-900/10 p-4 rounded-lg">
                        {toolData.error}
                    </p>
                </div>
            </div>
        );
    }

    // If no result yet, show waiting message
    if (!toolData.result) {
        return (
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
                <div className="p-6 text-center text-slate-500">
                    <span className="material-symbols-outlined text-4xl mb-2 block">
                        pending
                    </span>
                    <p className="text-sm">No results available yet</p>
                </div>
            </div>
        );
    }

    // Parse and display results
    const resultData = toolData.result;
    const isObject = typeof resultData === 'object' && resultData !== null;

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
                <h4 className="font-bold text-slate-900 dark:text-white text-sm">
                    Scan Results
                </h4>
                <button
                    onClick={() => setShowRaw(!showRaw)}
                    className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors px-3 py-1 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-500/10">
                    {showRaw ? "Show Formatted" : "Show Raw JSON"}
                </button>
            </div>
            <div className="p-6">
                {showRaw ? (
                    <pre className="text-xs font-mono text-slate-900 dark:text-white bg-slate-50 dark:bg-slate-800/50 p-4 rounded-lg overflow-x-auto border border-slate-200 dark:border-slate-700">
                        {JSON.stringify(resultData, null, 2)}
                    </pre>
                ) : (
                    <div className="space-y-4">
                        {isObject ? (
                            Object.entries(resultData).map(([key, value]) => (
                                <div key={key} className="border-b border-slate-200 dark:border-slate-700 pb-3 last:border-0">
                                    <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">
                                        {key.replace(/_/g, ' ')}
                                    </p>
                                    <div className="text-sm text-slate-900 dark:text-white">
                                        {typeof value === 'object' && value !== null ? (
                                            <pre className="font-mono text-xs bg-slate-50 dark:bg-slate-800/50 p-3 rounded-lg overflow-x-auto border border-slate-200 dark:border-slate-700">
                                                {JSON.stringify(value, null, 2)}
                                            </pre>
                                        ) : (
                                            <p className="font-medium">{String(value)}</p>
                                        )}
                                    </div>
                                </div>
                            ))
                        ) : (
                            <p className="text-sm text-slate-900 dark:text-white font-mono">
                                {String(resultData)}
                            </p>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
