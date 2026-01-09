"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { scannersApi, ToolKey } from "@/services/api";
import { parseToolResults } from "@/utils/toolParsers";

// --- Types ---

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface ScanVulnerability {
    id: string;
    name: string;
    severity: "Critical" | "High" | "Medium" | "Low" | "Info";
    description: string;
    tool: ToolKey;
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
    startScan: (target: string, selectedTools: ToolKey[], name?: string) => Promise<string>;
    deleteScan: (id: string) => void;
    isLoading: boolean;
}

// --- Helper Functions ---

const generateId = () => Math.random().toString(36).substring(2, 9);
const STORAGE_KEY = "napscan_jobs";

// --- Context ---

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export function ScanProvider({ children }: { children: React.ReactNode }) {
    const [scans, setScans] = useState<ScanJob[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    // Load from LocalStorage on mount
    useEffect(() => {
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                setScans(JSON.parse(stored));
            }
        } catch (error) {
            console.error("Failed to load scans", error);
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Save to LocalStorage whenever scans change
    useEffect(() => {
        if (!isLoading) {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
        }
    }, [scans, isLoading]);

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
    const executeOpenVAS = async (scanId: string, target: string) => {
        const tool: ToolKey = "openvas";
        updateToolStatus(scanId, tool, {
            status: "running",
            progress: 0,
            startTime: new Date().toISOString(),
        });

        try {
            // Step 1: Start Scan
            const startRes = await scannersApi.openvas.scan(target);
            if (!startRes.ok || !startRes.data?.taskID) {
                throw new Error((startRes as any).message || "Failed to start OpenVAS scan");
            }
            const taskId = startRes.data.taskID;

            // Step 2: Poll for status
            let reportId: string | undefined;
            let progress = 0;
            const POLL_INTERVAL = 5000; // 5 seconds
            const MAX_POLLS = 120; // Max 10 minutes

            for (let i = 0; i < MAX_POLLS; i++) {
                const statusRes = await scannersApi.openvas.taskStatus(taskId);
                if (!statusRes.ok) {
                    throw new Error((statusRes as any).message || "Failed to get OpenVAS status");
                }

                progress = statusRes.data?.progress ?? 0;
                updateToolStatus(scanId, tool, { progress });

                const status = statusRes.data?.status?.toLowerCase();
                if (status === "done" || status === "completed") {
                    reportId = statusRes.data?.reportID;
                    break;
                }
                if (status === "stopped" || status === "failed") {
                    throw new Error(`OpenVAS task ${status}`);
                }

                await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
            }

            if (!reportId) {
                throw new Error("OpenVAS scan timed out or no report ID");
            }

            // Step 3: Fetch Report
            const reportRes = await scannersApi.openvas.report(reportId);
            if (!reportRes.ok) {
                throw new Error((reportRes as any).message || "Failed to fetch OpenVAS report");
            }

            updateToolStatus(scanId, tool, {
                status: "completed",
                progress: 100,
                endTime: new Date().toISOString(),
                result: reportRes.data,
            });
        } catch (err: any) {
            console.error("OpenVAS failed", err);
            updateToolStatus(scanId, tool, {
                status: "failed",
                progress: 100,
                endTime: new Date().toISOString(),
                error: err.message,
            });
        }
    };

    // --- Generic Tool Executor ---
    const executeTool = async (scanId: string, tool: ToolKey, target: string) => {
        // OpenVAS has its own dedicated async handler
        if (tool === "openvas") {
            return executeOpenVAS(scanId, target);
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
                    result = await scannersApi.nmap.scan(target);
                    break;
                case "zap":
                    result = await scannersApi.zap.scan(target);
                    break;
                case "nuclei":
                    result = await scannersApi.nuclei.scan(target);
                    break;
                case "sslyze":
                    result = await scannersApi.sslyze.scan(target);
                    break;
                case "ffuf":
                    result = await scannersApi.ffuf.scan(target);
                    break;
                default:
                    throw new Error(`Unknown tool: ${tool}`);
            }

            const res = result as any;
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

    const startScan = async (target: string, selectedTools: ToolKey[], name?: string) => {
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

        // Start tools in "background" (no await here)
        // We execute them individually so they update independently
        selectedTools.forEach((tool) => {
            executeTool(newScanId, tool, target).then(() => {
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
