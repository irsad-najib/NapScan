"use client";

import { useScan } from "@/context/ScanContext";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import Link from "next/link";
import { ToolList } from "@/components/scans/ToolList";

export default function ScanDetailPage() {
    const params = useParams();
    const router = useRouter();
    const { getScan } = useScan();

    const scanId = params.id as string;
    const scan = getScan(scanId);

    // If scan is not found, we might be loading or ID is invalid
    // For context-based state, if it's missing it usually means invalid ID or lost state (reload)
    useEffect(() => {
        if (!scan) {
            // In a real app with backend, we would fetch here.
            // Since we use localStorage, if it's gone it's gone.
            // We'll give it a moment or redirect.
            const timer = setTimeout(() => {
                // Optionally redirect if still not found
                // router.push('/scans');
            }, 1000);
            return () => clearTimeout(timer);
        }
    }, [scan]);

    if (!scan) {
        return (
            <div className="flex h-screen w-full items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-500">
                <div className="text-center">
                    <span className="material-symbols-outlined text-4xl mb-2 animate-spin">sync</span>
                    <p>Loading scan details...</p>
                    <Link href="/scans" className="text-blue-500 hover:underline mt-4 block text-sm">
                        Back to Scans
                    </Link>
                </div>
            </div>
        );
    }

    // Calculate overall progress from tools
    const toolKeys = Object.keys(scan.tools);
    const totalProgress = toolKeys.reduce((acc, key) => acc + (scan.tools[key as any].progress || 0), 0);
    const avgProgress = toolKeys.length > 0 ? Math.round(totalProgress / toolKeys.length) : 0;

    // Override progress with 100 if status is completed
    const displayProgress = scan.status === "completed" ? 100 : avgProgress;

    return (
        <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
            {/* Simple Sidebar (Placeholder to match layout) */}
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
                    <Link href="/scans" className="flex items-center gap-3 px-4 py-3 rounded-xl bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 font-medium">
                        <span className="material-symbols-outlined">radar</span>
                        <span className="hidden md:block">Scans</span>
                    </Link>
                </nav>
            </aside>

            <div className="flex-1 flex flex-col h-full overflow-hidden relative">
                {/* Header */}
                <header className="h-16 flex items-center px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 backdrop-blur-sm shrink-0">
                    <div className="flex items-center gap-4">
                        <Link href="/scans" className="text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors">
                            <span className="material-symbols-outlined">arrow_back</span>
                        </Link>
                        <div>
                            <h1 className="text-lg font-bold text-slate-900 dark:text-white leading-tight">
                                {scan.name}
                            </h1>
                            <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
                                <span>{scan.target}</span>
                                <span>•</span>
                                <span>{new Date(scan.createdAt).toLocaleString()}</span>
                            </p>
                        </div>
                        <div className={`ml-4 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${scan.status === 'completed' ? 'bg-emerald-100 text-emerald-700' :
                                scan.status === 'running' ? 'bg-blue-100 text-blue-700' :
                                    'bg-slate-100 text-slate-700'
                            }`}>
                            {scan.status}
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
                                        {scan.status === 'completed' ? 'Scan completed successfully' : 'Scan in progress...'}
                                    </p>
                                </div>
                                <span className="text-3xl font-bold text-slate-900 dark:text-white">{displayProgress}%</span>
                            </div>
                            <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-3 overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all duration-500 ${scan.status === 'failed' ? 'bg-red-500' : 'bg-gradient-to-r from-blue-500 to-cyan-500'
                                        }`}
                                    style={{ width: `${displayProgress}%` }}
                                />
                            </div>
                        </div>

                        {/* Master List of Tools */}
                        <div className="animate-fade-in">
                            <ToolList
                                tools={scan.tools}
                                target={scan.target}
                                vulnerabilities={scan.vulnerabilities}
                            />
                        </div>

                    </div>
                </main>
            </div>
        </div>
    );
}
