"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { batchApi, BatchDetailResponse, ToolKey } from "@/services/api";
import { ToolGrid } from "@/components/scans/ToolGrid";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";

interface BatchDetailModalProps {
    batchId: string;
    onClose: () => void;
}

export function BatchDetailModal({ batchId, onClose }: BatchDetailModalProps) {
    const [batch, setBatch] = useState<BatchDetailResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchBatchDetails = async () => {
            if (!batchId) return;

            try {
                const response = await batchApi.get(batchId);
                // ApiResult is { ok: true, data: T } | { ok: false, message: string ... }
                if (response.ok) {
                    setBatch(response.data);
                } else {
                    setError(response.message || "Failed to fetch batch details");
                }
            } catch (err) {
                console.error("Error fetching batch details:", err);
                setError("An unexpected error occurred");
            } finally {
                setLoading(false);
            }
        };

        fetchBatchDetails();
        const interval = setInterval(fetchBatchDetails, 5000); // Poll for updates
        return () => clearInterval(interval);
    }, [batchId]);

    // Handle ESC key to close
    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => {
            if (e.key === "Escape") onClose();
        };
        window.addEventListener("keydown", handleEsc);
        return () => window.removeEventListener("keydown", handleEsc);
    }, [onClose]);

    if (loading) {
        return (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
                <div className="bg-white dark:bg-slate-900 rounded-2xl p-8 flex flex-col items-center shadow-xl border border-slate-200 dark:border-slate-800">
                    <span className="material-symbols-outlined text-4xl mb-2 animate-spin text-blue-500">sync</span>
                    <p className="text-slate-500 dark:text-slate-400">Loading details...</p>
                </div>
            </div>
        );
    }

    if (error || !batch) {
        return (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm">
                <div className="bg-white dark:bg-slate-900 rounded-2xl p-8 flex flex-col items-center shadow-xl border border-slate-200 dark:border-slate-800 max-w-sm text-center">
                    <span className="material-symbols-outlined text-4xl mb-2 text-red-500">error</span>
                    <p className="text-slate-900 dark:text-white font-medium mb-1">Error</p>
                    <p className="text-slate-500 dark:text-slate-400 text-sm mb-4">{error || "Scan not found"}</p>
                    <button
                        onClick={onClose}
                        className="px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors"
                    >
                        Close
                    </button>
                </div>
            </div>
        );
    }

    // transform Helper
    const validSeverities = ["Critical", "High", "Medium", "Low", "Info"];
    const normalizeSeverity = (sev: string): "Critical" | "High" | "Medium" | "Low" | "Info" => {
        if (!sev) return "Info";
        const titleCase = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
        if (validSeverities.includes(titleCase)) {
            return titleCase as "Critical" | "High" | "Medium" | "Low" | "Info";
        }
        return "Info";
    };

    // Transform Batch Data to ToolList Props
    const tools: Record<string, ToolExecution> = {};
    const vulnerabilities: ScanVulnerability[] = [];

    // Map scan_results to ToolExecution objects
    const scanResults = batch.scan_results || [];
    scanResults.forEach((result) => {
        // Normalize tool name from API (e.g. "owasp-zap" -> "zap")
        let toolName = result.tool;
        if (toolName === "owasp-zap") toolName = "zap";

        // Determine status based on batch status (simplification, ideally per tool status)
        const isCompleted = batch.status === "completed" || batch.status === "complete";
        const status = isCompleted ? "completed" : "running";

        tools[toolName] = {
            status: status,
            progress: isCompleted ? 100 : 50, // Dummy progress if not completed
            result: result, // Pass the full result object
            error: undefined,
            tool: toolName as ToolKey
        };
    });

    // Map risk_detail to Vulnerabilities
    const riskDetail = batch.risk_detail || [];
    riskDetail.forEach((risk) => {
        let toolName = risk.scanner;
        if (toolName === "owasp-zap") toolName = "zap";

        // Flatten findings into vulnerabilities
        if (risk.findings && Array.isArray(risk.findings)) {
            risk.findings.forEach((finding: any) => {
                vulnerabilities.push({
                    id: `${toolName}-${Math.random().toString(36).substr(2, 9)}`, // Generate ID if missing
                    tool: toolName as ToolKey,
                    severity: normalizeSeverity(finding.severity || risk.normalized_severity),
                    name: finding.name || risk.description,
                    description: finding.description || risk.description,
                    affectedAsset: finding.location || "N/A",
                });
            });
        }

        // If no findings but risk is reported, add a summary vulnerability if useful
        if ((!risk.findings || risk.findings.length === 0) && (risk.score > 0 || risk.normalized_severity === "INFO")) {
            vulnerabilities.push({
                id: `${toolName}-summary`,
                tool: toolName as ToolKey,
                severity: normalizeSeverity(risk.normalized_severity),
                name: risk.description,
                description: risk.description,
                affectedAsset: "Batch Summary",
            });
        }
    });

    // Calculate display progress
    const displayProgress = batch.status.toLowerCase() === "completed" || batch.status.toLowerCase() === "complete" ? 100 : 50;
    const statusColor =
        batch.status === 'completed' || batch.status === 'complete' ? 'bg-emerald-100 text-emerald-700' :
            batch.status === 'running' || batch.status === 'processing' ? 'bg-blue-100 text-blue-700' :
                'bg-slate-100 text-slate-700';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fade-in">
            {/* Modal Container */}
            <div className="bg-white dark:bg-slate-950 w-full max-w-6xl h-[90vh] rounded-2xl shadow-2xl flex flex-col overflow-hidden border border-slate-200 dark:border-slate-800">

                {/* Header */}
                <div className="h-16 flex items-center justify-between px-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shrink-0">
                    <div className="flex items-center gap-4">
                        <div>
                            <h2 className="text-lg font-bold text-slate-900 dark:text-white leading-tight">
                                Scan Details
                            </h2>
                            <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                                <span>{batch.target}</span>
                                <span>•</span>
                                <span>{new Date(batch.created_at).toLocaleString()}</span>
                            </p>
                        </div>
                        <div className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${statusColor}`}>
                            {batch.status}
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 -mr-2 text-slate-500 hover:text-slate-900 dark:hover:text-white rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                        aria-label="Close"
                    >
                        <span className="material-symbols-outlined">close</span>
                    </button>
                </div>

                {/* Scrollable Content */}
                <div className="flex-1 overflow-y-auto p-6 md:p-8 bg-slate-50 dark:bg-slate-950/50">

                    {/* Overall Progress Section */}
                    <div className="mb-8 bg-white dark:bg-slate-900 rounded-2xl p-6 border border-slate-200 dark:border-slate-800 shadow-sm">
                        <div className="flex items-center justify-between mb-4">
                            <div>
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Overall Progress</h3>
                                <p className="text-sm text-slate-500 dark:text-slate-400">
                                    {displayProgress === 100 ? 'Scan completed' : 'Scan in progress...'}
                                </p>
                            </div>
                            <span className="text-3xl font-bold text-slate-900 dark:text-white">{displayProgress}%</span>
                        </div>
                        <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-3 overflow-hidden">
                            <div
                                className={`h-full rounded-full transition-all duration-500 ${batch.status === 'failed' ? 'bg-red-500' : 'bg-gradient-to-r from-blue-500 to-cyan-500'}`}
                                style={{ width: `${displayProgress}%` }}
                            />
                        </div>
                    </div>

                    {/* Master List of Tools - GRID VIEW */}
                    <ToolGrid
                        tools={tools as any}
                        target={batch.target}
                        vulnerabilities={vulnerabilities}
                        scanId={batch.batch_id}
                    />
                </div>
            </div>
        </div>
    );
}
