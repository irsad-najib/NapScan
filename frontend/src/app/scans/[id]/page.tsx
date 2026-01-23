"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";
import { batchApi, BatchDetailResponse, ToolKey } from "@/services/api";
import { ToolList } from "@/components/scans/ToolList";
import { ToolExecution, ScanVulnerability } from "@/context/ScanContext";

export default function ScanDetailPage() {
    const params = useParams();
    const router = useRouter();
    const [batch, setBatch] = useState<BatchDetailResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const scanId = params.id as string;

    useEffect(() => {
        const fetchBatchDetails = async () => {
            if (!scanId) return;

            try {
                const response = await batchApi.get(scanId);
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
    }, [scanId]);

    if (loading) {
        return (
            <div className="flex h-screen w-full items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-500">
                <div className="text-center">
                    <span className="material-symbols-outlined text-4xl mb-2 animate-spin">sync</span>
                    <p>Loading scan details...</p>
                    <Link href="/" className="text-blue-500 hover:underline mt-4 block text-sm">
                        Back to Dashboard
                    </Link>
                </div>
            </div>
        );
    }

    if (error || !batch) {
        return (
            <div className="flex h-screen w-full items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-500">
                <div className="text-center">
                    <span className="material-symbols-outlined text-4xl mb-2 text-red-500">error</span>
                    <p>{error || "Scan not found"}</p>
                    <Link href="/" className="text-blue-500 hover:underline mt-4 block text-sm">
                        Back to Dashboard
                    </Link>
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
        const status = batch.status === "completed" ? "completed" : "running";

        tools[toolName] = {
            status: status,
            progress: status === "completed" ? 100 : 50, // Dummy progress if not completed
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
                    // Detail is not in ScanVulnerability interface, using description/name/affectedAsset to convey info
                });
            });
        }

        // If no findings but risk is reported, add a summary vulnerability if useful
        if ((!risk.findings || risk.findings.length === 0) && risk.score > 0) {
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
        <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
            {/* Simple Sidebar */}
            <aside className="w-16 md:w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 hidden md:flex flex-col">
                <div className="p-6">
                    <Link href="/" className="flex items-center gap-3">
                        <div className="bg-gradient-to-br from-blue-500 to-cyan-500 size-8 rounded-lg flex items-center justify-center">
                            <span className="material-symbols-outlined text-white text-sm">shield_lock</span>
                        </div>
                        <span className="font-bold text-slate-900 dark:text-white hidden md:block">NapScan</span>
                    </Link>
                </div>
                <nav className="flex-1 px-4 space-y-1">
                    <Link href="/" className="flex items-center gap-3 px-4 py-3 rounded-xl bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 font-medium">
                        <span className="material-symbols-outlined">dashboard</span>
                        <span className="hidden md:block">Dashboard</span>
                    </Link>
                </nav>
            </aside>

            <div className="flex-1 flex flex-col h-full overflow-hidden relative">
                {/* Header */}
                <header className="h-16 flex items-center px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 backdrop-blur-sm shrink-0">
                    <div className="flex items-center gap-4">
                        <Link href="/" className="text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors">
                            <span className="material-symbols-outlined">arrow_back</span>
                        </Link>
                        <div>
                            <h1 className="text-lg font-bold text-slate-900 dark:text-white leading-tight">
                                Scan Details
                            </h1>
                            <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                                <span>{batch.target}</span>
                                <span>•</span>
                                <span>{new Date(batch.created_at).toLocaleString()}</span>
                            </p>
                        </div>
                        <div className={`ml-4 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${statusColor}`}>
                            {batch.status}
                        </div>
                    </div>
                </header>

                {/* Main Content */}
                <main className="flex-1 overflow-y-auto p-8">
                    <div className="max-w-6xl mx-auto">

                        {/* Overall Progress Section */}
                        <div className="mb-10 bg-white dark:bg-slate-900 rounded-2xl p-6 border border-slate-200 dark:border-slate-800 shadow-sm">
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
                                    className={`h-full rounded-full transition-all duration-500 ${batch.status === 'failed' ? 'bg-red-500' : 'bg-gradient-to-r from-blue-500 to-cyan-500'
                                        }`}
                                    style={{ width: `${displayProgress}%` }}
                                />
                            </div>
                        </div>

                        {/* Master List of Tools */}
                        <div className="animate-fade-in">
                            <ToolList
                                tools={tools as any}
                                target={batch.target}
                                vulnerabilities={vulnerabilities}
                                scanId={batch.batch_id}
                            />
                        </div>

                    </div>
                </main>
            </div>
        </div>
    );
}
