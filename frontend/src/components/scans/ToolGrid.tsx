"use client";

import React, { useState } from "react";
import { ToolKey } from "@/services/api";
import { ToolExecution, ScanVulnerability, useScan } from "@/context/ScanContext";
import { ToolCard } from "./ToolCard";
import { ToolMetadata } from "./ToolMetadata";
import { ToolRiskOverview } from "./ToolRiskOverview";

interface ToolGridProps {
    tools: Record<ToolKey, ToolExecution>;
    target: string;
    vulnerabilities: ScanVulnerability[];
    scanId?: string;
}

export function ToolGrid({ tools, target, vulnerabilities, scanId }: ToolGridProps) {
    const [selectedToolKey, setSelectedToolKey] = useState<ToolKey | null>(null);
    const { pendingDecisions, submitMobSFDecision, stopTool } = useScan();
    const sortedKeys = Object.keys(tools) as ToolKey[];

    const selectedTool = selectedToolKey ? tools[selectedToolKey] : null;
    const selectedToolVulns = selectedToolKey ? vulnerabilities.filter(v => v.tool === selectedToolKey) : [];

    const [isStopping, setIsStopping] = useState(false);
    const [isSubmittingDecision, setIsSubmittingDecision] = useState(false);

    const handleStop = async () => {
        if (!scanId || !selectedToolKey) return;
        setIsStopping(true);
        try {
            await stopTool(scanId, selectedToolKey);
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

    return (
        <>
            {/* Grid Layout */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {sortedKeys.map((key) => (
                    <ToolCard
                        key={key}
                        tool={key}
                        data={tools[key]}
                        vulnerabilities={vulnerabilities}
                        onClick={() => setSelectedToolKey(key)}
                    />
                ))}
            </div>

            {/* Modal */}
            {selectedToolKey && selectedTool && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in">
                    <div className="bg-white dark:bg-slate-900 rounded-2xl w-full max-w-5xl h-[90vh] flex flex-col shadow-2xl overflow-hidden">
                        {/* Modal Header */}
                        <div className="flex items-center justify-between p-6 border-b border-slate-100 dark:border-slate-800 bg-white dark:bg-slate-900">
                            <div className="flex items-center gap-4">
                                <button
                                    onClick={() => setSelectedToolKey(null)}
                                    className="p-2 -ml-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 transition-colors"
                                >
                                    <span className="material-symbols-outlined">arrow_back</span>
                                </button>
                                <div>
                                    <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                                        {getToolName(selectedToolKey)}
                                        <span className={`text-xs px-2.5 py-1 rounded-full border uppercase tracking-wider font-bold 
                                            ${selectedTool.status === 'completed' ? 'bg-emerald-50 text-emerald-600 border-emerald-200' :
                                                selectedTool.status === 'failed' ? 'bg-red-50 text-red-600 border-red-200' :
                                                    'bg-blue-50 text-blue-600 border-blue-200'}`}>
                                            {selectedTool.status}
                                        </span>
                                    </h2>
                                    <p className="text-sm text-slate-500">{target}</p>
                                </div>
                            </div>

                            <div className="flex items-center gap-2">
                                {/* Stop Button for Running Tools */}
                                {selectedTool.status === 'running' && ['nmap', 'ffuf', 'sslyze', 'zap'].includes(selectedToolKey) && (
                                    <button
                                        onClick={handleStop}
                                        disabled={isStopping}
                                        className="flex items-center gap-2 px-4 py-2 text-red-600 bg-red-50 hover:bg-red-100 rounded-lg text-sm font-bold transition-colors disabled:opacity-50"
                                    >
                                        <span className={`material-symbols-outlined ${isStopping ? 'animate-spin' : ''}`}>
                                            {isStopping ? 'sync' : 'stop_circle'}
                                        </span>
                                        {isStopping ? 'Stopping...' : 'Stop Scan'}
                                    </button>
                                )}
                                <button
                                    onClick={() => setSelectedToolKey(null)}
                                    className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-red-500 transition-colors"
                                >
                                    <span className="material-symbols-outlined">close</span>
                                </button>
                            </div>
                        </div>

                        {/* Modal Content */}
                        <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-slate-50/50 dark:bg-black/20">
                            {/* MobSF Decision UI */}
                            {selectedToolKey === 'mobsf' && selectedTool.status === 'awaiting_decision' && (
                                <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-700/50 rounded-xl p-6 mb-6">
                                    <div className="flex items-start justify-between">
                                        <div className="flex gap-4">
                                            <div className="p-3 bg-amber-100 dark:bg-amber-800/30 rounded-full text-amber-600 dark:text-amber-400">
                                                <span className="material-symbols-outlined text-2xl">help_center</span>
                                            </div>
                                            <div>
                                                <h3 className="font-bold text-lg text-slate-900 dark:text-white mb-1">Action Required</h3>
                                                <p className="text-slate-600 dark:text-slate-300">Static analysis is complete. How would you like to proceed?</p>
                                            </div>
                                        </div>
                                        <div className="flex gap-3">
                                            <button
                                                onClick={() => handleDecision("STOP")}
                                                disabled={isSubmittingDecision}
                                                className="px-4 py-2 bg-white border border-slate-200 text-slate-700 font-bold rounded-lg hover:bg-slate-50 disabled:opacity-50"
                                            >
                                                Stop Here
                                            </button>
                                            <button
                                                onClick={() => handleDecision("CONTINUE")}
                                                disabled={isSubmittingDecision}
                                                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold rounded-lg hover:from-purple-700 hover:to-blue-700 disabled:opacity-50 shadow-lg shadow-blue-500/20"
                                            >
                                                Continue Dynamic Analysis
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Tool Content */}
                            {selectedToolVulns.length > 0 && <ToolRiskOverview vulnerabilities={selectedToolVulns} />}
                            <ToolMetadata toolData={selectedTool} target={target} />
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
