"use client";

import React from "react";
import { ScanVulnerability } from "@/context/ScanContext";

interface ToolRiskOverviewProps {
    vulnerabilities: ScanVulnerability[];
}

export function ToolRiskOverview({ vulnerabilities }: ToolRiskOverviewProps) {
    const counts = {
        critical: vulnerabilities.filter((v) => v.severity.toLowerCase() === "critical").length,
        high: vulnerabilities.filter((v) => v.severity.toLowerCase() === "high").length,
        medium: vulnerabilities.filter((v) => v.severity.toLowerCase() === "medium").length,
        low: vulnerabilities.filter((v) => v.severity.toLowerCase() === "low").length,
        info: vulnerabilities.filter((v) => v.severity.toLowerCase() === "info").length,
    };

    const total = vulnerabilities.length;

    // Calculate percentages for bar (prevent div by zero)
    const getPercent = (count: number) => total > 0 ? (count / total) * 100 : 0;

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6">
                <h4 className="font-bold text-slate-900 dark:text-white">Risks Overview</h4>
                <span className="text-xs font-semibold text-slate-500 uppercase">
                    {total} Total Issues
                </span>
            </div>

            <div className="flex flex-wrap gap-8 justify-between">
                {/* Critical */}
                <div className="flex flex-col items-center gap-1">
                    <span className="text-2xl font-bold text-red-600 dark:text-red-500">{counts.critical}</span>
                    <div className="flex items-center gap-1.5">
                        <span className="size-2 rounded-full bg-red-500"></span>
                        <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase">Critical</span>
                    </div>
                </div>

                {/* High */}
                <div className="flex flex-col items-center gap-1">
                    <span className="text-2xl font-bold text-orange-600 dark:text-orange-500">{counts.high}</span>
                    <div className="flex items-center gap-1.5">
                        <span className="size-2 rounded-full bg-orange-500"></span>
                        <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase">High</span>
                    </div>
                </div>

                {/* Medium */}
                <div className="flex flex-col items-center gap-1">
                    <span className="text-2xl font-bold text-amber-500 dark:text-amber-400">{counts.medium}</span>
                    <div className="flex items-center gap-1.5">
                        <span className="size-2 rounded-full bg-amber-500"></span>
                        <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase">Medium</span>
                    </div>
                </div>

                {/* Low */}
                <div className="flex flex-col items-center gap-1">
                    <span className="text-2xl font-bold text-blue-600 dark:text-blue-500">{counts.low}</span>
                    <div className="flex items-center gap-1.5">
                        <span className="size-2 rounded-full bg-blue-500"></span>
                        <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase">Low</span>
                    </div>
                </div>
            </div>

            {/* Visual Bar */}
            <div className="mt-8 flex h-3 w-full rounded-full overflow-hidden bg-slate-100 dark:bg-slate-800">
                {counts.critical > 0 && <div style={{ width: `${getPercent(counts.critical)}%` }} className="h-full bg-red-500" />}
                {counts.high > 0 && <div style={{ width: `${getPercent(counts.high)}%` }} className="h-full bg-orange-500" />}
                {counts.medium > 0 && <div style={{ width: `${getPercent(counts.medium)}%` }} className="h-full bg-amber-500" />}
                {counts.low > 0 && <div style={{ width: `${getPercent(counts.low)}%` }} className="h-full bg-blue-500" />}
                {counts.info > 0 && <div style={{ width: `${getPercent(counts.info)}%` }} className="h-full bg-slate-400" />}
            </div>
        </div>
    );
}
