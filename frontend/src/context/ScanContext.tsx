"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { scannersApi, batchApi, ToolKey } from "@/services/api";
import { parseToolResults } from "@/utils/toolParsers";

// --- Types ---

export type ScanStatus = "pending" | "running" | "completed" | "failed";

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
}

export interface ScanJob {
    id: string;
    name: string;
    target: string;
    status: ScanStatus;
    createdAt: string;
    updatedAt: string;
    tools: Record<ToolKey, ToolExecution>;
    vulnerabilities: ScanVulnerability[];
}

interface ScanContextType {
    scans: ScanJob[];
    currentScan: ScanJob | null;
    getScan: (id: string) => ScanJob | undefined;
    startScan: (target: string, selectedTools: ToolKey[], name?: string, apkFile?: File) => Promise<string>;
    deleteScan: (id: string) => void;
    isLoading: boolean;
}

// --- Helper Functions ---

const generateId = () => Math.random().toString(36).substring(2, 9);

// --- Context ---

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
    const [scans, setScans] = useState<ScanJob[]>([]);
    // No more loading state since we don't load from localStorage
    const [isLoading] = useState(false);

    const getScan = useCallback((id: string) => {
        return scans.find((s) => s.id === id);
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

    // --- OpenVAS Dedicated Handler (3-step async flow) ---
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

            // Step 2: Poll for status (no timeout - wait until done)
            let reportId: string | undefined;
            let progress = 0;
            const POLL_INTERVAL = 15000; // 15 seconds
            let pollCount = 0;

            console.log(`[OpenVAS] Step 2: Polling for status (no timeout, interval ${POLL_INTERVAL}ms)...`);

            while (true) {
                pollCount++;
                console.log(`[OpenVAS] Poll #${pollCount}...`);
                const statusRes = await scannersApi.openvas.taskStatus(taskId);
                console.log(`[OpenVAS] Status response:`, statusRes);

                if (!statusRes.ok) {
                    console.error(`[OpenVAS] Status check failed:`, statusRes);
                    throw new Error((statusRes as any).message || (statusRes as any).error || "Failed to get OpenVAS status");
                }

                // Handle nested data structure
                const statusData = (statusRes.data as any)?.data || statusRes.data;
                progress = statusData?.progress ?? 0;
                const status = statusData?.status?.toLowerCase();
                console.log(`[OpenVAS] Progress: ${progress}%, Status: ${status}`);

                updateToolStatus(scanId, tool, { progress });

                if (status === "done" || status === "completed") {
                    reportId = statusData?.reportID;
                    console.log(`[OpenVAS] Scan completed! reportID: ${reportId}`);
                    break;
                }
                if (status === "stopped" || status === "failed" || status === "error") {
                    throw new Error(`OpenVAS task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }

            if (!reportId) {
                throw new Error("No report ID returned from OpenVAS");
            }

            // Step 3: Fetch Report
            console.log(`[OpenVAS] Step 3: Fetching report ${reportId}...`);
            const reportRes = await scannersApi.openvas.report(reportId);
            console.log(`[OpenVAS] Report response:`, reportRes);

            if (!reportRes.ok) {
                console.error(`[OpenVAS] Report fetch failed:`, reportRes);
                throw new Error((reportRes as any).message || (reportRes as any).error || "Failed to fetch OpenVAS report");
            }

            console.log(`[OpenVAS] Scan completed successfully!`);
            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: reportRes.data,
            });

            // Parse vulnerabilities from report
            try {
                const toolVulns = parseToolResults(tool, reportRes.data);
                console.log(`[OpenVAS] Parsed ${toolVulns.length} vulnerabilities`);
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
            console.error("[OpenVAS] Failed:", err);
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

            // Step 2: Poll for status (until completed)
            let progress = 0;
            const POLL_INTERVAL = 10000; // 10 seconds
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

    // --- MobSF Dedicated Handler (2-step async flow: upload + scan) ---
    const executeMobSF = async (scanId: string, apkFile: File, batchId?: string) => {
        const tool: ToolKey = "mobsf";
        console.log(`[MobSF] Starting scan for APK: ${apkFile.name}${batchId ? `, batchId: ${batchId}` : ''}`);

        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Upload APK
            console.log(`[MobSF] Step 1: Uploading APK file...`);
            updateToolStatus(scanId, tool, { progress: 10 });

            const uploadRes = await scannersApi.mobsf.upload(apkFile, batchId);
            console.log(`[MobSF] Upload response:`, uploadRes);

            if (!uploadRes.ok) {
                console.error(`[MobSF] Upload failed:`, uploadRes);
                throw new Error((uploadRes as any).message || "Failed to upload APK");
            }

            // Handle nested data structure - response is { success, message, data: { file_name, hash, scan_type, upload } }
            const uploadData = (uploadRes.data as any)?.data || uploadRes.data;
            const hash = uploadData?.hash;
            const fileName = uploadData?.file_name;
            const scanType = uploadData?.scan_type;

            if (!hash || !fileName || !scanType) {
                console.error(`[MobSF] Missing required data in upload response:`, uploadRes.data);
                throw new Error("Missing hash, file_name, or scan_type from MobSF upload");
            }

            console.log(`[MobSF] APK uploaded - hash: ${hash}, file: ${fileName}, type: ${scanType}`);
            updateToolStatus(scanId, tool, { progress: 40 });

            // Step 2: Scan using hash, file_name, scan_type, batch_id
            console.log(`[MobSF] Step 2: Starting scan...`);
            const scanRes = await scannersApi.mobsf.scan({
                hash,
                file_name: fileName,
                scan_type: scanType,
                ...(batchId && { batch_id: batchId })
            });
            console.log(`[MobSF] Scan response:`, scanRes);

            if (!scanRes.ok) {
                console.error(`[MobSF] Scan failed:`, scanRes);
                throw new Error((scanRes as any).message || "Failed to scan APK");
            }

            // Handle nested data structure
            const scanData = (scanRes.data as any)?.data || scanRes.data;

            console.log(`[MobSF] Scan completed successfully!`);
            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: scanData,
            });

            // Parse vulnerabilities from scan result
            try {
                const toolVulns = parseToolResults(tool, scanData);
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

        // Mark tool as running
        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            let result;
            switch (tool) {
                case "nmap":
                    result = await scannersApi.nmap.scan(target, batchId);
                    break;
                case "zap":
                    result = await scannersApi.zap.scan(target, batchId);
                    break;
                case "sslyze":
                    result = await scannersApi.sslyze.scan(target, batchId);
                    break;
                case "ffuf":
                    result = await scannersApi.ffuf.scan(target, batchId);
                    break;
                default:
                    throw new Error(`Unknown tool: ${tool}`);
            }

            const res = result as any;

            // Special handling for SSLyze - it may return HTTP 500 but still have valid results
            // SSLyze exits with status 1 when compliance check fails, but scan data is in the error/data field
            // Check both res.data (for HTTP 200 with success:false) and res.data (for HTTP 500 error body)
            if (tool === "sslyze") {
                const sslyzeData = res.data as { success?: boolean; error?: string; message?: string } | undefined;
                const errorStr = sslyzeData?.error || res.message || "";

                console.log(`[ScanContext] SSLyze response:`, { ok: res.ok, hasData: !!sslyzeData, errorLength: errorStr.length });

                if (typeof errorStr === "string" && errorStr.includes("SCAN RESULTS FOR")) {
                    console.log(`[ScanContext] SSLyze has scan results in response, parsing...`);

                    // Store the data even though it's technically a "failure"
                    updateToolStatus(scanId, tool, {
                        status: "completed",
                        progress: 100,
                        endTime: new Date().toISOString(),
                        result: sslyzeData || { error: errorStr },
                    });

                    // Parse vulnerabilities from the response
                    try {
                        const toolVulns = parseToolResults(tool, sslyzeData || { error: errorStr });
                        console.log(`[ScanContext] Parsed ${toolVulns.length} SSLyze vulnerabilities:`, toolVulns);
                        if (toolVulns.length > 0) {
                            const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                                ...v,
                                id: `${scanId}-${tool}-${idx}`,
                            }));
                            addVulnerabilities(scanId, scanVulns);
                        }
                    } catch (parseError) {
                        console.error(`Failed to parse SSLyze results:`, parseError);
                    }
                    return; // Exit early, don't throw error
                }
            }

            if (!res.ok) {
                throw new Error(res.error || res.message || "Unknown error");
            }

            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: res.data,
            });

            // Parse tool results and extract vulnerabilities
            if (res.data) {
                console.log(`[ScanContext] Parsing ${tool} results:`, res.data);
                try {
                    const toolVulns = parseToolResults(tool, res.data);
                    console.log(`[ScanContext] Parsed ${toolVulns.length} vulnerabilities:`, toolVulns);
                    if (toolVulns.length > 0) {
                        const scanVulns: ScanVulnerability[] = toolVulns.map((v, idx) => ({
                            ...v,
                            id: `${scanId}-${tool}-${idx}`,
                        }));
                        console.log(`[ScanContext] Adding vulnerabilities to scan:`, scanVulns);
                        addVulnerabilities(scanId, scanVulns);
                    }
                } catch (parseError) {
                    console.error(`Failed to parse ${tool} results:`, parseError);
                }
            }
        } catch (err: any) {
            console.error(`Tool ${tool} failed`, err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
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
                // Check if all tools finished
                setScans((currentScans) => {
                    const s = currentScans.find(scan => scan.id === newScanId);
                    if (!s) return currentScans;

                    const allTools = Object.values(s.tools);
                    const allFinished = allTools.every(t => t.status === 'completed' || t.status === 'failed');

                    if (allFinished) {
                        return currentScans.map(scan =>
                            scan.id === newScanId
                                ? { ...scan, status: 'completed', updatedAt: new Date().toISOString() }
                                : scan
                        );
                    }
                    return currentScans;
                });
            });
        });

        return newScanId;
    };

    const deleteScan = (id: string) => {
        setScans((prev) => prev.filter((s) => s.id !== id));
    };

    return (
        <ScanContext.Provider
            value={{
                scans,
                currentScan: null,
                getScan,
                startScan,
                deleteScan,
                isLoading,
            }}
        >
            {children}
        </ScanContext.Provider>
    );
}

export function useScan() {
    const context = useContext(ScanContext);
    if (context === undefined) {
        throw new Error("useScan must be used within a ScanProvider");
    }
    return context;
}
