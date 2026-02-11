"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { scannersApi, batchApi, ToolKey } from "@/services/api";
import { parseToolResults } from "@/utils/toolParsers";
import { inflateRawSync } from "zlib";

// --- Types ---

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "awaiting_decision";

export interface ScanVulnerability {
    id: string;
    name: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    description: string;
    tool: ToolKey;
    // Optional fields for detailed vulnerability data (Nuclei, etc.)
    affectedAsset?: string;
    recommendation?: string;
    cweId?: string;
    cveId?: string | null;
    references?: string[];
    tags?: string[];
    templateId?: string;
    matcherName?: string;
}

export interface ToolExecution {
    tool: ToolKey;
    status: ScanStatus;
    progress: number;
    result?: any;
    error?: string;
    startTime?: string;
    endTime?: string;
    // For async tools - track task_id for stop functionality
    taskId?: string;
    // MobSF specific - for tracking file status
    fileId?: number;
}

export interface ScanJob {
    id: string;
    batchId?: string;
    name: string;
    target: string;
    status: ScanStatus;
    createdAt: string;
    updatedAt: string;
    tools: Partial<Record<ToolKey, ToolExecution>>;
    vulnerabilities: ScanVulnerability[];
}

// MobSF pending decision - when awaiting user input
export interface MobSFPendingDecision {
    scanId: string;
    fileId: number;
    fileName: string;
    appName: string;
    packageName: string;
    securityScore: string;
    severityCounts: {
        high: number;
        warning: number;
        info: number;
    };
    mobsfResult: any;
}

interface ScanContextType {
    scans: ScanJob[];
    currentScan: ScanJob | null;
    getScan: (id: string) => ScanJob | undefined;
    startScan: (target: string, selectedTools: ToolKey[], name?: string, apkFile?: File) => Promise<string>;
    deleteScan: (id: string) => void;
    stopTool: (scanId: string, tool: ToolKey) => Promise<void>;
    isLoading: boolean;
    // MobSF decision flow
    pendingDecisions: MobSFPendingDecision[];
    submitMobSFDecision: (scanId: string, decision: "STOP" | "CONTINUE") => Promise<void>;
}

// --- Helper Functions ---

const generateId = () => Math.random().toString(36).substring(2, 9);

// --- LocalStorage Helper ---
const SCANS_STORAGE_KEY = 'napscan_scans';
const PENDING_DECISIONS_KEY = 'napscan_pending_decisions';

const isBrowser = typeof window !== 'undefined';

const saveScansToStorage = (scans: ScanJob[]) => {
    if (!isBrowser) return;
    try {
        sessionStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(scans));
    } catch (e) {
        console.error('[ScanContext] Failed to save scans to sessionStorage:', e);
    }
};

const loadScansFromStorage = (): ScanJob[] => {
    if (!isBrowser) return [];
    try {
        const data = sessionStorage.getItem(SCANS_STORAGE_KEY);
        if (data) {
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('[ScanContext] Failed to load scans from sessionStorage:', e);
    }
    return [];
};

const savePendingDecisionsToStorage = (decisions: MobSFPendingDecision[]) => {
    if (!isBrowser) return;
    try {
        sessionStorage.setItem(PENDING_DECISIONS_KEY, JSON.stringify(decisions));
    } catch (e) {
        console.error('[ScanContext] Failed to save pending decisions to sessionStorage:', e);
    }
};

const loadPendingDecisionsFromStorage = (): MobSFPendingDecision[] => {
    if (!isBrowser) return [];
    try {
        const data = sessionStorage.getItem(PENDING_DECISIONS_KEY);
        if (data) {
            return JSON.parse(data);
        }
    } catch (e) {
        console.error('[ScanContext] Failed to load pending decisions from sessionStorage:', e);
    }
    return [];
};

// --- Context ---

const ScanContext = createContext<ScanContextType | undefined>(undefined);

const DELETED_BATCHES_KEY = 'napscan_deleted_batches';

const loadDeletedBatchesFromStorage = (): Set<string> => {
    if (!isBrowser) return new Set();
    try {
        const data = sessionStorage.getItem(DELETED_BATCHES_KEY);
        if (data) {
            return new Set(JSON.parse(data));
        }
    } catch (e) {
        console.error('[ScanContext] Failed to load deleted batches from sessionStorage:', e);
    }
    return new Set();
};

const saveDeletedBatchesToStorage = (ids: Set<string>) => {
    if (!isBrowser) return;
    try {
        sessionStorage.setItem(DELETED_BATCHES_KEY, JSON.stringify(Array.from(ids)));
    } catch (e) {
        console.error('[ScanContext] Failed to save deleted batches to sessionStorage:', e);
    }
};

export function ScanProvider({ children }: { children: React.ReactNode }) {
    const [scans, setScans] = useState<ScanJob[]>(() => loadScansFromStorage());
    const [isLoading, setIsLoading] = useState(true);
    // MobSF pending decisions - scans waiting for user to decide STOP/CONTINUE
    const [pendingDecisions, setPendingDecisions] = useState<MobSFPendingDecision[]>(() => loadPendingDecisionsFromStorage());
    // Track which tools are already being polled to prevent duplicate polling
    const [pollingTools, setPollingTools] = useState<Set<string>>(new Set());

    // Track deleted batch IDs to prevent them from re-appearing during sync
    const [deletedBatchIds, setDeletedBatchIds] = useState<Set<string>>(() => loadDeletedBatchesFromStorage());

    // --- Save deleted batches to localStorage whenever they change ---
    useEffect(() => {
        saveDeletedBatchesToStorage(deletedBatchIds);
    }, [deletedBatchIds]);

    // --- Sync Scans from Backend (Batch History) ---
    const syncScansFromBatchHistory = useCallback(async () => {
        // console.log("[ScanContext] Syncing scans from batch history...");
        try {
            const res = await batchApi.list();
            if (!res.ok || !res.data) return;

            setScans((prevScans) => {
                let hasChanges = false;
                const newScans = [...prevScans];
                const backendBatches = res.data;

                // 1. Update existing scans and add new ones from backend
                backendBatches.forEach((batch) => {
                    // Skip if this batch was explicitly deleted by the user
                    if (deletedBatchIds.has(batch.batch_id)) {
                        return;
                    }

                    const existingIndex = newScans.findIndex((s) => s.id === batch.batch_id || s.batchId === batch.batch_id);

                    if (existingIndex !== -1) {
                        // Update existing scan status if backend has newer info
                        const backendStatus = batch.status.toLowerCase();
                        if (newScans[existingIndex].status !== backendStatus &&
                            (backendStatus === 'completed' || backendStatus === 'failed')) {
                            newScans[existingIndex] = {
                                ...newScans[existingIndex],
                                status: backendStatus as ScanStatus,
                                updatedAt: batch.timestamp,
                            };
                            hasChanges = true;
                        }
                    } else {
                        // Add new scan from backend (e.g. Scheduled Scans)
                        newScans.unshift({
                            id: batch.batch_id,
                            batchId: batch.batch_id,
                            name: `Scan ${batch.timestamp.substring(0, 10)}`, // Generate a name or use target
                            target: batch.target,
                            status: batch.status.toLowerCase() as ScanStatus,
                            createdAt: batch.timestamp,
                            updatedAt: batch.timestamp,
                            tools: {}, // We don't know tools from list, detail page will fetch
                            vulnerabilities: [],
                        });
                        hasChanges = true;
                    }
                });

                return hasChanges ? newScans : prevScans;
            });
        } catch (err) {
            console.error("[ScanContext] Failed to sync batch history:", err);
        }
    }, [deletedBatchIds]); // Depend on deletedBatchIds so callback updates when it changes

    // Initial load from backend
    // Initial load from backend - DISABLED to make Scans page ephemeral per user request
    // useEffect(() => {
    //     syncScansFromBatchHistory();
    //     // Optional: Poll occasionally for new scheduled scans
    //     const interval = setInterval(syncScansFromBatchHistory, 10000);
    //     return () => clearInterval(interval);
    // }, [syncScansFromBatchHistory]);

    // --- Save scans to localStorage whenever they change ---
    useEffect(() => {
        saveScansToStorage(scans);
    }, [scans]);

    // --- Save pending decisions to localStorage whenever they change ---
    useEffect(() => {
        savePendingDecisionsToStorage(pendingDecisions);
    }, [pendingDecisions]);

    // --- Monitor for scan completion ---
    useEffect(() => {
        scans.forEach(scan => {
            if (scan.status === 'running') {
                const tools = Object.values(scan.tools);
                if (tools.length > 0 && tools.every(t => t.status === 'completed' || t.status === 'failed')) {
                    console.log(`[ScanContext] Auto-marking scan ${scan.id} as completed`);
                    // Use a direct state update to avoid dependency cycles with updateScan helper
                    setScans((prev) =>
                        prev.map((s) => {
                            if (s.id !== scan.id) return s;
                            return { ...s, status: 'completed', updatedAt: new Date().toISOString() };
                        })
                    );
                }
            }
        });
    }, [scans]);


    const updateScan = (id: string, updates: Partial<ScanJob>) => {
        setScans((prev) =>
            prev.map((scan) => {
                if (scan.id !== id) return scan;
                return { ...scan, ...updates, updatedAt: new Date().toISOString() };
            })
        );
    };

    const updateToolStatus = (
        scanId: string,
        tool: ToolKey,
        updates: Partial<ToolExecution>
    ) => {
        setScans((prev) =>
            prev.map((scan) => {
                if (scan.id !== scanId) return scan;
                const currentToolState = scan.tools[tool];
                return {
                    ...scan,
                    updatedAt: new Date().toISOString(),
                    tools: {
                        ...scan.tools,
                        [tool]: { ...currentToolState, ...updates },
                    },
                };
            })
        );
    };

    const addVulnerabilities = (scanId: string, vulns: ScanVulnerability[]) => {
        setScans((prev) =>
            prev.map((scan) => {
                if (scan.id !== scanId) return scan;
                return {
                    ...scan,
                    vulnerabilities: [...scan.vulnerabilities, ...vulns],
                };
            })
        );
    };

    // Helper function to check and update overall scan status
    const checkAndUpdateScanStatus = (scanId: string) => {
        setScans((currentScans) => {
            const scan = currentScans.find(s => s.id === scanId);
            if (!scan) return currentScans;

            const allTools = Object.values(scan.tools);
            // Check if all tools are in a terminal state (completed, failed)
            // Note: awaiting_decision is NOT terminal - scan should stay running while waiting
            const allFinished = allTools.every(t =>
                t.status === 'completed' || t.status === 'failed'
            );

            if (allFinished && scan.status !== 'completed') {
                console.log(`[ScanContext] All tools finished for scan ${scanId}, marking scan as completed`);
                return currentScans.map(s =>
                    s.id === scanId
                        ? { ...s, status: 'completed' as ScanStatus, updatedAt: new Date().toISOString() }
                        : s
                );
            }
            return currentScans;
        });
    };

    // --- OpenVAS Dedicated Handler (3-step async flow) ---
    const monitorOpenVAS = async (scanId: string, taskId: string) => {
        const tool: ToolKey = "openvas";
        const pollKey = `${scanId}-${tool}`;

        if (pollingTools.has(pollKey)) {
            console.log(`[OpenVAS] Already monitoring ${pollKey}`);
            return;
        }

        setPollingTools((prev) => new Set(prev).add(pollKey));
        console.log(`[OpenVAS] Monitor started for task: ${taskId}`);

        try {
            // Step 2: Poll for status
            let reportId: string | undefined;
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;
            let failureCount = 0;
            const MAX_FAILURES = 5;

            console.log(`[OpenVAS] Monitoring status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;

                let statusRes;
                try {
                    statusRes = await scannersApi.openvas.taskStatus(taskId);
                } catch (netErr) {
                    console.error(`[OpenVAS] Network error polling status:`, netErr);
                    statusRes = { ok: false, error: netErr };
                }

                if (!statusRes || !statusRes.ok) {
                    failureCount++;
                    console.warn(`[OpenVAS] Status check failed (Attempt ${failureCount}/${MAX_FAILURES})`);

                    if (failureCount >= MAX_FAILURES) {
                        throw new Error((statusRes as any)?.message || (statusRes as any)?.error || "Failed to get OpenVAS status after multiple attempts");
                    }

                    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
                    continue;
                }

                failureCount = 0;

                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();

                // Only log every few polls to reduce noise
                if (pollCount % 4 === 1) console.log(`[OpenVAS] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    reportId = statusData?.reportID || statusData?.reportId;
                    console.log(`[OpenVAS] Scan completed! reportID: ${reportId}`);
                    break;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(`OpenVAS task ${status}`);
                }
            }

            if (!reportId) {
                throw new Error("No report ID returned from OpenVAS");
            }

            // Step 3: Fetch Report
            console.log(`[OpenVAS] Step 3: Fetching report ${reportId}...`);
            const reportRes = await scannersApi.openvas.report(reportId);

            if (!reportRes.ok) {
                throw new Error((reportRes as any).message || (reportRes as any).error || "Failed to fetch OpenVAS report");
            }

            console.log(`[OpenVAS] Scan completed successfully!`);
            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: reportRes.data,
            });

            try {
                const toolVulns = parseToolResults(tool, reportRes.data);
                if (toolVulns.length > 0) {
                    const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                        ...v,
                        id: `${scanId}-${tool}-${idx}`,
                    }));
                    addVulnerabilities(scanId, scanVulns);
                }
            } catch (parseError) {
                console.error(`[OpenVAS] Failed to parse results:`, parseError);
            }
        } catch (err: any) {
            console.error("[OpenVAS] Monitor Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        } finally {
            setPollingTools((prev) => {
                const next = new Set(prev);
                next.delete(pollKey);
                return next;
            });
        }
    };

    const executeOpenVAS = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "openvas";
        console.log(`[OpenVAS] Starting scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Scan
            console.log(`[OpenVAS] Step 1: Starting scan...`);
            const startRes = await scannersApi.openvas.scan(target, undefined, batchId);
            console.log(`[OpenVAS] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[OpenVAS] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start OpenVAS scan");
            }

            // Handle nested data structure: startRes.data = {success, message, data: {taskID, ...}}
            const responseData = (startRes.data as any)?.data || startRes.data;
            const taskId = responseData?.taskID;

            if (!taskId) {
                console.error(`[OpenVAS] No taskID in response:`, startRes.data);
                throw new Error("No taskID returned from OpenVAS");
            }

            console.log(`[OpenVAS] Scan started, taskID: ${taskId}`);

            // Save taskId and start monitoring
            updateToolStatus(scanId, tool, { taskId });
            monitorOpenVAS(scanId, taskId);

        } catch (err: any) {
            console.error("[OpenVAS] Start Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- Nmap Dedicated Handler (async flow with progress) ---
    const monitorNmap = async (scanId: string, taskId: string) => {
        const tool: ToolKey = "nmap";
        const pollKey = `${scanId}-${tool}`;

        if (pollingTools.has(pollKey)) {
            console.log(`[Nmap] Already monitoring ${pollKey}`);
            return;
        }
        setPollingTools((prev) => new Set(prev).add(pollKey));

        console.log(`[Nmap] Monitor started for task: ${taskId}`);

        try {
            let progress = 0;
            const POLL_INTERVAL = 15000;
            let failureCount = 0;
            const MAX_FAILURES = 5;

            console.log(`[Nmap] Monitoring status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                let statusRes;
                try {
                    statusRes = await scannersApi.nmap.taskStatus(taskId);
                } catch (netErr) {
                    console.error(`[Nmap] Network error polling status:`, netErr);
                    statusRes = { ok: false, error: netErr };
                }

                if (!statusRes || !statusRes.ok) {
                    failureCount++;
                    console.warn(`[Nmap] Status check failed (Attempt ${failureCount}/${MAX_FAILURES})`);
                    if (failureCount >= MAX_FAILURES) {
                        throw new Error((statusRes as any)?.message || (statusRes as any)?.error || "Failed to get Nmap status after multiple attempts");
                    }
                    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
                    continue;
                }

                failureCount = 0;
                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();

                // Only log every few polls to reduce noise
                // if (pollCount % 4 === 1) console.log(`[Nmap] Progress: ${progress}%, Status: ${status}`);
                console.log(`[Nmap] Progress: ${progress}%, Status: ${status}`); // Keep original Nmap logging for now

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[Nmap] Scan completed!`);
                    const result = statusData?.result || [];

                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: result,
                    });

                    try {
                        const toolVulns = parseToolResults(tool, result);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[Nmap] Failed to parse results:`, parseError);
                    }
                    break;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(statusData?.error || `Nmap task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error("[Nmap] Monitor Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                endTime: new Date().toISOString(),
                error: err.message,
            });
        } finally {
            setPollingTools((prev) => {
                const next = new Set(prev);
                next.delete(pollKey);
                return next;
            });
        }
    };

    const executeNmap = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "nmap";
        console.log(`[Nmap] Starting async scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Async Scan
            console.log(`[Nmap] Step 1: Starting async scan...`);
            const startRes = await scannersApi.nmap.scanAsync(target, batchId);
            console.log(`[Nmap] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[Nmap] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start Nmap scan");
            }

            // Handle nested data structure
            const responseData = (startRes.data as any)?.data || startRes.data;
            const taskId = responseData?.task_id;

            if (!taskId) {
                console.error(`[Nmap] No task_id in response:`, startRes.data);
                throw new Error("No task_id returned from Nmap");
            }

            console.log(`[Nmap] Scan started, task_id: ${taskId}`);

            // Save taskId for stop functionality and start monitoring
            updateToolStatus(scanId, tool, { taskId });
            monitorNmap(scanId, taskId);
        } catch (err: any) {
            console.error("[Nmap] Start Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- FFUF Dedicated Handler (async flow with progress) ---
    const executeFfuf = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "ffuf";
        console.log(`[FFUF] Starting async scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Async Scan
            console.log(`[FFUF] Step 1: Starting async scan...`);
            const startRes = await scannersApi.ffuf.scanAsync(target, batchId);
            console.log(`[FFUF] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[FFUF] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start FFUF scan");
            }

            // Handle nested data structure
            const responseData = (startRes.data as any)?.data || startRes.data;
            const taskId = responseData?.task_id;

            if (!taskId) {
                console.error(`[FFUF] No task_id in response:`, startRes.data);
                throw new Error("No task_id returned from FFUF");
            }

            console.log(`[FFUF] Scan started, task_id: ${taskId}`);

            // Save taskId for stop functionality
            updateToolStatus(scanId, tool, { taskId });

            // Step 2: Poll for status (until completed)
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[FFUF] Step 2: Polling for status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[FFUF] Poll #${pollCount}...`);
                const statusRes = await scannersApi.ffuf.taskStatus(taskId);
                console.log(`[FFUF] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[FFUF] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || (statusRes as any).error || "Failed to get FFUF status");
                }

                // Handle nested data structure
                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();
                console.log(`[FFUF] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[FFUF] Scan completed!`);

                    // Extract result from status response
                    const result = statusData?.result || [];

                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: result,
                    });

                    // Parse vulnerabilities from result
                    try {
                        const toolVulns = parseToolResults(tool, result);
                        console.log(`[FFUF] Parsed ${toolVulns.length} vulnerabilities`);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[FFUF] Failed to parse results:`, parseError);
                    }
                    return;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(statusData?.error || `FFUF task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error("[FFUF] Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- SSLyze Dedicated Handler (async flow with progress) ---
    const executeSslyze = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "sslyze";
        console.log(`[SSLyze] Starting async scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Async Scan
            console.log(`[SSLyze] Step 1: Starting async scan...`);
            const startRes = await scannersApi.sslyze.scanAsync(target, batchId);
            console.log(`[SSLyze] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[SSLyze] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start SSLyze scan");
            }

            // Handle nested data structure
            const responseData = (startRes.data as any)?.data || startRes.data;
            const taskId = responseData?.task_id;

            if (!taskId) {
                console.error(`[SSLyze] No task_id in response:`, startRes.data);
                throw new Error("No task_id returned from SSLyze");
            }

            console.log(`[SSLyze] Scan started, task_id: ${taskId}`);

            // Save taskId for stop functionality
            updateToolStatus(scanId, tool, { taskId });

            // Step 2: Poll for status (until completed)
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[SSLyze] Step 2: Polling for status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[SSLyze] Poll #${pollCount}...`);
                const statusRes = await scannersApi.sslyze.taskStatus(taskId);
                console.log(`[SSLyze] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[SSLyze] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || (statusRes as any).error || "Failed to get SSLyze status");
                }

                // Handle nested data structure
                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();
                console.log(`[SSLyze] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[SSLyze] Scan completed!`);

                    // Extract result from status response
                    const result = statusData?.result || [];

                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: result,
                    });

                    // Parse vulnerabilities from result
                    try {
                        const toolVulns = parseToolResults(tool, result);
                        console.log(`[SSLyze] Parsed ${toolVulns.length} vulnerabilities`);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[SSLyze] Failed to parse results:`, parseError);
                    }
                    return;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(statusData?.error || `SSLyze task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error("[SSLyze] Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- ZAP Dedicated Handler (async flow with progress) ---
    const executeZap = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "zap";
        console.log(`[ZAP] Starting async scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Async Scan
            console.log(`[ZAP] Step 1: Starting async scan...`);
            const startRes = await scannersApi.zap.scanAsync(target, batchId);
            console.log(`[ZAP] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[ZAP] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start ZAP scan");
            }

            // Handle nested data structure
            const responseData = (startRes.data as any)?.data || startRes.data;
            const taskId = responseData?.task_id;

            if (!taskId) {
                console.error(`[ZAP] No task_id in response:`, startRes.data);
                throw new Error("No task_id returned from ZAP");
            }

            console.log(`[ZAP] Scan started, task_id: ${taskId}`);

            // Save taskId for stop functionality
            updateToolStatus(scanId, tool, { taskId });

            // Step 2: Poll for status (until completed)
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[ZAP] Step 2: Polling for status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[ZAP] Poll #${pollCount}...`);
                const statusRes = await scannersApi.zap.taskStatus(taskId);
                console.log(`[ZAP] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[ZAP] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || (statusRes as any).error || "Failed to get ZAP status");
                }

                // Handle nested data structure
                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();
                console.log(`[ZAP] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[ZAP] Scan completed!`);

                    // Extract result from status response
                    const result = statusData?.result || [];

                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: result,
                    });

                    // Parse vulnerabilities from result
                    try {
                        const toolVulns = parseToolResults(tool, result);
                        console.log(`[ZAP] Parsed ${toolVulns.length} vulnerabilities`);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[ZAP] Failed to parse results:`, parseError);
                    }
                    return;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(statusData?.error || `ZAP task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error("[ZAP] Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- Nuclei Dedicated Handler (3-step async flow) ---
    const executeNuclei = async (scanId: string, target: string, batchId?: string) => {
        const tool: ToolKey = "nuclei";
        console.log(`[Nuclei] Starting async scan for target: ${target}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Async Scan
            console.log(`[Nuclei] Step 1: Starting async scan...`);
            const startRes = await scannersApi.nuclei.scanAsync(target, batchId);
            console.log(`[Nuclei] Start response:`, startRes);

            if (!startRes.ok) {
                console.error(`[Nuclei] Start scan failed:`, startRes);
                throw new Error((startRes as any).message || (startRes as any).error || "Failed to start Nuclei scan");
            }

            const taskId = startRes.data?.task_id;

            if (!taskId) {
                console.error(`[Nuclei] No task_id in response:`, startRes.data);
                throw new Error("No task_id returned from Nuclei");
            }

            console.log(`[Nuclei] Scan started, task_id: ${taskId}`);

            // Save taskId for stop functionality
            updateToolStatus(scanId, tool, { taskId });

            // Step 2: Poll for status (until completed)
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[Nuclei] Step 2: Polling for status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[Nuclei] Poll #${pollCount}...`);
                const statusRes = await scannersApi.nuclei.taskStatus(taskId);
                console.log(`[Nuclei] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[Nuclei] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || (statusRes as any).error || "Failed to get Nuclei status");
                }

                progress = statusRes.data?.progress ?? 0;
                const status = statusRes.data?.status?.toLowerCase();
                console.log(`[Nuclei] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[Nuclei] Scan completed!`);
                    break;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(`Nuclei task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }

            // Step 3: Fetch Result
            console.log(`[Nuclei] Step 3: Fetching result for task ${taskId}...`);
            const resultRes = await scannersApi.nuclei.result(taskId);
            console.log(`[Nuclei] Result response:`, resultRes);

            if (!resultRes.ok) {
                console.error(`[Nuclei] Result fetch failed:`, resultRes);
                throw new Error((resultRes as any).message || (resultRes as any).error || "Failed to fetch Nuclei result");
            }

            // Extract nested data - actual results are in data.data
            const nucleiData = resultRes.data?.data || resultRes.data;
            console.log(`[Nuclei] Scan completed successfully! Found ${nucleiData?.results?.length || 0} findings`);

            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: nucleiData,
            });

            // Parse vulnerabilities from result
            try {
                const toolVulns = parseToolResults(tool, nucleiData);
                console.log(`[Nuclei] Parsed ${toolVulns.length} vulnerabilities`);
                if (toolVulns.length > 0) {
                    const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                        ...v,
                        id: `${scanId}-${tool}-${idx}`,
                    }));
                    addVulnerabilities(scanId, scanVulns);
                }
            } catch (parseError) {
                console.error(`[Nuclei] Failed to parse results:`, parseError);
            }
        } catch (err: any) {
            console.error("[Nuclei] Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- MobSF Dedicated Handler (async flow with user decision) ---
    const executeMobSF = async (scanId: string, apkFile: File, batchId?: string) => {
        const tool: ToolKey = "mobsf";
        console.log(`[MobSF] Starting scan for APK: ${apkFile.name}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Upload APK (triggers MobSF scan automatically)
            console.log(`[MobSF] Step 1: Uploading APK file...`);
            updateToolStatus(scanId, tool, { progress: 10 });

            const uploadRes = await scannersApi.mobsf.upload(apkFile, batchId);
            console.log(`[MobSF] Upload response:`, uploadRes);

            if (!uploadRes.ok) {
                console.error(`[MobSF] Upload failed:`, uploadRes);
                throw new Error((uploadRes as any).message || "Failed to upload APK");
            }

            // Get file_id from response
            const uploadData = (uploadRes.data as any)?.data || uploadRes.data;
            const fileId = uploadData?.file_id;
            const fileName = uploadData?.file_name;

            if (!fileId) {
                console.error(`[MobSF] No file_id in upload response:`, uploadRes.data);
                throw new Error("No file_id returned from MobSF upload");
            }

            console.log(`[MobSF] APK uploaded - file_id: ${fileId}, file: ${fileName}`);
            updateToolStatus(scanId, tool, { progress: 20, fileId });

            // Step 2: Poll for status until WAITING_USER_DECISION or terminal state
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[MobSF] Step 2: Polling for status (interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[MobSF] Poll #${pollCount}...`);

                const statusRes = await scannersApi.mobsf.fileStatus(fileId);
                console.log(`[MobSF] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[MobSF] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || "Failed to get MobSF status");
                }

                const statusData = (statusRes.data as any)?.data || statusRes.data;
                const status = statusData?.status;
                console.log(`[MobSF] Current status: ${status}`);

                // Update progress based on status
                if (status === "MOBSF_RUNNING") {
                    updateToolStatus(scanId, tool, { progress: 30 + Math.min(pollCount * 5, 40) });
                }

                if (status === "WAITING_USER_DECISION") {
                    console.log(`[MobSF] Scan complete, waiting for user decision`);

                    // Extract MobSF findings for display
                    const findings = statusData?.findings?.mobsf;
                    const identity = findings?.identity || {};
                    const findingsSummary = findings?.findings || {};

                    const pendingDecision: MobSFPendingDecision = {
                        scanId,
                        fileId,
                        fileName: identity.file_name || fileName,
                        appName: identity.app_name || "Unknown App",
                        packageName: identity.package_name || "Unknown Package",
                        securityScore: findingsSummary.security_score || "N/A",
                        severityCounts: {
                            high: findingsSummary.totals?.high || 0,
                            warning: findingsSummary.totals?.warning || 0,
                            info: findingsSummary.totals?.info || 0,
                        },
                        mobsfResult: statusData,
                    };

                    // Add to pending decisions
                    setPendingDecisions(prev => [...prev, pendingDecision]);

                    // Update tool status to awaiting_decision
                    updateToolStatus(scanId, tool, {
                        status: "awaiting_decision",
                        progress: 70,
                        result: statusData,
                    });

                    // Stop polling - wait for user decision via submitMobSFDecision
                    return;
                }

                if (status === "COMPLETED") {
                    console.log(`[MobSF] Scan fully completed!`);
                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: statusData,
                    });

                    // Parse vulnerabilities
                    try {
                        const toolVulns = parseToolResults(tool, statusData);
                        console.log(`[MobSF] Parsed ${toolVulns.length} vulnerabilities`);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[MobSF] Failed to parse results:`, parseError);
                    }
                    return;
                }

                if (status === "FAILED") {
                    throw new Error(statusData?.error || "MobSF scan failed");
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error("[MobSF] Failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- Generic Tool Executor ---
    const executeTool = async (scanId: string, tool: ToolKey, target: string, apkFile?: File, batchId?: string) => {
        // OpenVAS has its own dedicated async handler
        if (tool === "openvas") {
            return executeOpenVAS(scanId, target, batchId);
        }

        // Nuclei has its own dedicated async handler
        if (tool === "nuclei") {
            return executeNuclei(scanId, target, batchId);
        }

        // Nmap has its own dedicated async handler
        if (tool === "nmap") {
            return executeNmap(scanId, target, batchId);
        }

        // FFUF has its own dedicated async handler
        if (tool === "ffuf") {
            return executeFfuf(scanId, target, batchId);
        }

        // SSLyze has its own dedicated async handler
        if (tool === "sslyze") {
            return executeSslyze(scanId, target, batchId);
        }

        // ZAP has its own dedicated async handler
        if (tool === "zap") {
            return executeZap(scanId, target, batchId);
        }

        // MobSF has its own dedicated async handler
        if (tool === "mobsf") {
            if (!apkFile) {
                console.error("[MobSF] No APK file provided");
                updateToolStatus(scanId, tool, {
                    status: "failed",
                    error: "No APK file provided",
                    endTime: new Date().toISOString(),
                });
                return;
            }
            return executeMobSF(scanId, apkFile, batchId);
        }

        // All tools are now using dedicated async handlers above
        // Only Frida remains handled by MobSF flow
        throw new Error(`Unknown tool: ${tool}`);
    };

    const startScan = async (target: string, selectedTools: ToolKey[], name?: string, apkFile?: File) => {
        const newScanId = generateId();
        const timestamp = new Date().toISOString();

        const toolsInit: Record<ToolKey, ToolExecution> = {} as any;
        selectedTools.forEach((tool) => {
            toolsInit[tool] = {
                tool,
                status: "pending",
                progress: 0,
            };
        });

        const newScan: ScanJob = {
            id: newScanId,
            name: name || `Scan ${target}`,
            target,
            status: "running",
            createdAt: timestamp,
            updatedAt: timestamp,
            tools: toolsInit,
            vulnerabilities: [],
        };

        setScans((prev) => [newScan, ...prev]);

        // Step 1: Create a batch first
        let batchId: string | undefined;
        try {
            console.log(`[ScanContext] Creating batch...`);
            const batchRes = await batchApi.create();
            console.log(`[ScanContext] Batch create response:`, batchRes);

            if (batchRes.ok && batchRes.data) {
                // Response is { batch_id: "xxx" }
                batchId = batchRes.data.batch_id;

                if (batchId) {
                    console.log(`[ScanContext] ✅ Batch created with ID: ${batchId}`);
                    // Update scan with batchId
                    setScans((prev) => prev.map(s =>
                        s.id === newScanId ? { ...s, batchId } : s
                    ));
                } else {
                    console.error(`[ScanContext] ❌ batch_id not found in response:`, batchRes.data);
                }
            } else {
                console.error(`[ScanContext] ❌ Batch create failed:`, batchRes);
            }
        } catch (err) {
            console.error(`[ScanContext] ❌ Error creating batch:`, err);
        }

        if (!batchId) {
            console.warn(`[ScanContext] ⚠️ Proceeding without batchId - scans may fail if backend requires it`);
        }

        // Step 2: Start tools in "background" with batchId
        selectedTools.forEach((tool) => {
            executeTool(newScanId, tool, target, apkFile, batchId).then(() => {
                // Check if all tools finished and update overall scan status
                checkAndUpdateScanStatus(newScanId);
            });
        });

        return newScanId;
    };

    const deleteScan = async (id: string) => {
        // Optimistically remove from UI
        setScans((prev) => prev.filter((s) => s.id !== id));

        // Remove from backend if it has a batchId
        // Find the scan first to get batchId (we need to do this before setting state, 
        // but since we're inside the function we can lookup from current state 'scans')
        // Note: scans might have been updated by setScans above in next render, but here 'scans' is closed over
        const scanToDelete = scans.find(s => s.id === id);
        if (scanToDelete?.batchId) {
            const batchId = scanToDelete.batchId;
            // Track this ID as deleted to prevent re-sync
            setDeletedBatchIds(prev => {
                const newSet = new Set(prev);
                newSet.add(batchId);
                return newSet;
            });

            try {
                console.log(`[ScanContext] Deleting batch ${batchId} from backend...`);
                await batchApi.delete(batchId);
                console.log(`[ScanContext] Batch deleted successfully`);
            } catch (err) {
                console.error(`[ScanContext] Failed to delete batch ${batchId}:`, err);
                // Optionally revert UI change here if critical, but for now we prioritize UI responsiveness
            }
        }
    };

    // Stop a running tool scan
    const stopTool = async (scanId: string, tool: ToolKey) => {
        const scan = scans.find(s => s.id === scanId);
        if (!scan) {
            console.error(`[StopTool] Scan not found: ${scanId}`);
            return;
        }

        const toolExecution = scan.tools[tool];
        if (!toolExecution || toolExecution.status !== 'running') {
            console.error(`[StopTool] Tool ${tool} is not running`);
            return;
        }

        const taskId = toolExecution.taskId;
        if (!taskId) {
            console.error(`[StopTool] No taskId found for tool ${tool}`);
            return;
        }

        console.log(`[StopTool] Stopping ${tool} with taskId: ${taskId}`);

        try {
            let stopRes;
            switch (tool) {
                case 'nmap':
                    stopRes = await scannersApi.nmap.stop(taskId);
                    break;
                case 'ffuf':
                    stopRes = await scannersApi.ffuf.stop(taskId);
                    break;
                case 'sslyze':
                    stopRes = await scannersApi.sslyze.stop(taskId);
                    break;
                case 'zap':
                    stopRes = await scannersApi.zap.stop(taskId);
                    break;
                case 'nuclei':
                    stopRes = await scannersApi.nuclei.stop(taskId);
                    break;
                case 'openvas':
                    stopRes = await scannersApi.openvas.stop(taskId);
                    break;
                default:
                    console.error(`[StopTool] Tool ${tool} does not support stop`);
                    return;
            }

            if (stopRes.ok) {
                console.log(`[StopTool] Successfully stopped ${tool}`);
                updateToolStatus(scanId, tool, {
                    status: 'failed',
                    progress: 100,
                    endTime: new Date().toISOString(),
                    error: 'Scan stopped by user',
                });
                checkAndUpdateScanStatus(scanId);
            } else {
                console.error(`[StopTool] Failed to stop ${tool}:`, stopRes);
            }
        } catch (err: any) {
            console.error(`[StopTool] Error stopping ${tool}:`, err);
        }
    };

    // Submit user decision for MobSF scan (STOP or CONTINUE with Frida)
    const submitMobSFDecision = async (scanId: string, decision: "STOP" | "CONTINUE") => {
        const pending = pendingDecisions.find(p => p.scanId === scanId);
        if (!pending) {
            console.error(`[MobSF] No pending decision found for scanId: ${scanId}`);
            return;
        }

        console.log(`[MobSF] Submitting decision: ${decision} for file_id: ${pending.fileId}`);
        const tool: ToolKey = "mobsf";

        try {
            // Submit decision to backend
            const decisionRes = await scannersApi.mobsf.submitDecision(pending.fileId, decision);
            console.log(`[MobSF] Decision response:`, decisionRes);

            if (!decisionRes.ok) {
                throw new Error((decisionRes as any).message || "Failed to submit decision");
            }

            // Remove from pending decisions
            setPendingDecisions(prev => prev.filter(p => p.scanId !== scanId));

            if (decision === "STOP") {
                // Mark as completed with current MobSF results
                updateToolStatus(scanId, tool, {
                    status: "completed",
                    progress: 100,
                    endTime: new Date().toISOString(),
                });

                // Parse vulnerabilities from MobSF result
                try {
                    const toolVulns = parseToolResults(tool, pending.mobsfResult);
                    console.log(`[MobSF] Parsed ${toolVulns.length} vulnerabilities`);
                    if (toolVulns.length > 0) {
                        const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                            ...v,
                            id: `${scanId}-${tool}-${idx}`,
                        }));
                        addVulnerabilities(scanId, scanVulns);
                    }
                } catch (parseError) {
                    console.error(`[MobSF] Failed to parse results:`, parseError);
                }
            } else {
                // CONTINUE - Update status to running and poll for Frida completion
                updateToolStatus(scanId, tool, {
                    status: "running",
                    progress: 75,
                });

                // Poll for Frida completion
                const POLL_INTERVAL = 15000;
                let pollCount = 0;

                console.log(`[MobSF] Continuing with Frida, polling for completion...`);

                while (true) {
                    pollCount++;
                    console.log(`[MobSF/Frida] Poll #${pollCount}...`);

                    const statusRes = await scannersApi.mobsf.fileStatus(pending.fileId);
                    console.log(`[MobSF/Frida] Status response:`, statusRes);

                    if (!statusRes.ok) {
                        throw new Error((statusRes as any).message || "Failed to get status");
                    }

                    const statusData = (statusRes.data as any)?.data || statusRes.data;
                    const status = statusData?.status;
                    console.log(`[MobSF/Frida] Current status: ${status}`);

                    if (status === "FRIDA_RUNNING") {
                        updateToolStatus(scanId, tool, { progress: 75 + Math.min(pollCount * 3, 20) });
                    }

                    if (status === "COMPLETED") {
                        console.log(`[MobSF/Frida] Scan fully completed!`);
                        updateToolStatus(scanId, tool, {
                            status: "completed",
                            progress: 100,
                            endTime: new Date().toISOString(),
                            result: statusData,
                        });

                        // Parse vulnerabilities
                        try {
                            const toolVulns = parseToolResults(tool, statusData);
                            console.log(`[MobSF] Parsed ${toolVulns.length} vulnerabilities`);
                            if (toolVulns.length > 0) {
                                const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                    ...v,
                                    id: `${scanId}-${tool}-${idx}`,
                                }));
                                addVulnerabilities(scanId, scanVulns);
                            }
                        } catch (parseError) {
                            console.error(`[MobSF] Failed to parse results:`, parseError);
                        }
                        break;
                    }

                    if (status === "FAILED") {
                        throw new Error(statusData?.error || "Frida scan failed");
                    }

                    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
                }
            }
        } catch (err: any) {
            console.error("[MobSF] Decision failed:", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
            // Remove from pending on error too
            setPendingDecisions(prev => prev.filter(p => p.scanId !== scanId));
        }

        // After decision is processed, check if overall scan should be completed
        checkAndUpdateScanStatus(scanId);
    };

    // --- Resume polling for running scans on page load ---
    const resumeToolPolling = useCallback(async (scanId: string, tool: ToolKey, taskId: string) => {
        const pollingKey = `${scanId}-${tool}`;

        // Prevent duplicate polling
        if (pollingTools.has(pollingKey)) {
            console.log(`[Resume] Already polling ${tool} for scan ${scanId}`);
            return;
        }

        setPollingTools(prev => new Set(prev).add(pollingKey));
        console.log(`[Resume] Resuming polling for ${tool} (taskId: ${taskId}) in scan ${scanId}`);

        const POLL_INTERVALS: Record<string, number> = {
            nmap: 15000,
            ffuf: 15000,
            sslyze: 15000,
            zap: 15000,
            nuclei: 15000,
            openvas: 15000,
        };

        const POLL_INTERVAL = POLL_INTERVALS[tool] || 15000;

        try {
            while (true) {
                let statusRes: any;

                // Call appropriate status API based on tool
                switch (tool) {
                    case 'nmap':
                        statusRes = await scannersApi.nmap.taskStatus(taskId);
                        break;
                    case 'ffuf':
                        statusRes = await scannersApi.ffuf.taskStatus(taskId);
                        break;
                    case 'sslyze':
                        statusRes = await scannersApi.sslyze.taskStatus(taskId);
                        break;
                    case 'zap':
                        statusRes = await scannersApi.zap.taskStatus(taskId);
                        break;
                    case 'nuclei':
                        statusRes = await scannersApi.nuclei.taskStatus(taskId);
                        break;
                    case 'openvas':
                        statusRes = await scannersApi.openvas.taskStatus(taskId);
                        break;
                    default:
                        console.warn(`[Resume] Unsupported tool for resume: ${tool}`);
                        return;
                }

                if (!statusRes.ok) {
                    console.error(`[Resume] ${tool} status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || `Failed to get ${tool} status`);
                }

                const statusData = (statusRes.data as any)?.data || statusRes.data;
                const progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();

                console.log(`[Resume] ${tool} Progress: ${progress}%, Status: ${status}`);
                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    console.log(`[Resume] ${tool} completed!`);

                    // Get result based on tool type
                    let result = statusData?.result || [];

                    // For Nuclei, we need to fetch the result separately
                    if (tool === 'nuclei') {
                        const resultRes = await scannersApi.nuclei.result(taskId);
                        if (resultRes.ok) {
                            result = resultRes.data?.data || resultRes.data;
                        }
                    }

                    // For OpenVAS, fetch the report
                    if (tool === 'openvas') {
                        const reportId = statusData?.reportID || statusData?.reportId;
                        if (reportId) {
                            const reportRes = await scannersApi.openvas.report(reportId);
                            if (reportRes.ok) {
                                result = reportRes.data;
                            }
                        }
                    }

                    // Format result based on tool
                    const formattedResult = tool === 'nmap'
                        ? { tcp: result, udp: [] }
                        : result;

                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: formattedResult,
                    });

                    // Parse vulnerabilities
                    try {
                        const toolVulns = parseToolResults(tool, formattedResult);
                        console.log(`[Resume] ${tool} parsed ${toolVulns.length} vulnerabilities`);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`[Resume] ${tool} failed to parse results:`, parseError);
                    }

                    checkAndUpdateScanStatus(scanId);
                    break;
                }

                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(statusData?.error || `${tool} task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }
        } catch (err: any) {
            console.error(`[Resume] ${tool} failed:`, err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
            checkAndUpdateScanStatus(scanId);
        } finally {
            setPollingTools(prev => {
                const next = new Set(prev);
                next.delete(pollingKey);
                return next;
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pollingTools]);

    // --- Effect to resume polling on mount ---
    useEffect(() => {
        if (scans.length > 0) {
            console.log("[ScanContext] Checking for running scans to resume...");
            scans.forEach((scan) => {
                Object.entries(scan.tools).forEach(([toolKey, execution]) => {
                    const tKey = toolKey as ToolKey;
                    if (execution.status === "running" && execution.taskId) {
                        console.log(`[ScanContext] Resuming monitor for ${tKey} in scan ${scan.id}`);
                        switch (tKey) {
                            case "openvas":
                                monitorOpenVAS(scan.id, execution.taskId);
                                break;
                            case "nmap":
                                monitorNmap(scan.id, execution.taskId);
                                break;
                            // Add other tools here when refactored
                        }
                    }
                });
            });
        }
    }, []); // Run once on mount

    const getScan = useCallback((id: string) => {
        return scans.find((s) => s.id === id);
    }, [scans]);

    const value = {
        scans,
        currentScan: null, // derived if needed
        getScan,
        startScan,
        deleteScan,
        stopTool,
        isLoading,
        pendingDecisions,
        submitMobSFDecision,
    };

    return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan() {
    const context = useContext(ScanContext);
    if (context === undefined) {
        throw new Error("useScan must be used within a ScanProvider");
    }
    return context;
}