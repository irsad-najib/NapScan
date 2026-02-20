"use client";

import { useState, useMemo, useEffect } from "react";
import Link from "next/link";
import { Sidebar, Header } from "@/components/layout";
import { batchApi, BatchItem, BatchDetailResponse, ToolKey } from "@/services/api";
import { ScanVulnerability } from "@/context/ScanContext";

// Severity priority map (higher value = more severe)
const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

type SortOrder = "desc" | "asc";

interface DetailedScanView {
  id: string; // batch_id
  name: string;
  target: string;
  status: string;
  createdAt: string;
  vulnerabilities: ScanVulnerability[];
  tools: Record<string, any>;
}

export default function ReportsPage() {
  const [batches, setBatches] = useState<BatchItem[]>([]);
  const [loadingBatches, setLoadingBatches] = useState(true);
  const [selectedBatchId, setSelectedBatchId] = useState<string | null>(null);

  // Detailed scan data for preview
  const [selectedScan, setSelectedScan] = useState<DetailedScanView | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  // PDF Preview State
  const [showPreview, setShowPreview] = useState(false);
  const [pdfBlobUrl, setPdfBlobUrl] = useState<string | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  const [exportFormat, setExportFormat] = useState<"pdf" | "html">("pdf");
  const [vulnSortOrder, setVulnSortOrder] = useState<SortOrder>("desc");
  const [isExporting, setIsExporting] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredBatches = useMemo(() => {
    if (!searchQuery) return batches;
    return batches.filter(batch =>
      batch.target.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [batches, searchQuery]);

  // 1. Fetch Batch List on Mount
  useEffect(() => {
    const fetchBatches = async () => {
      try {
        const res = await batchApi.list();
        if (res.ok && res.data) {
          setBatches(res.data);
        }
      } catch (err) {
        console.error("Failed to fetch reports list:", err);
      } finally {
        setLoadingBatches(false);
      }
    };
    fetchBatches();
  }, []);

  // 2. Fetch Detail when Selection Changes
  useEffect(() => {
    // Reset preview state whenever selection changes
    setPdfBlobUrl(null);
    setShowPreview(false);

    if (!selectedBatchId) {
      setSelectedScan(null);
      return;
    }

    const fetchDetail = async () => {
      setLoadingPreview(true);
      // Reset preview state slightly to show loading if desired, 
      // but keeping old data while loading new one might be better UX? 
      // Let's clear it to avoid confusion.
      setSelectedScan(null);

      try {
        const res = await batchApi.get(selectedBatchId);
        if (res.ok && res.data) {
          const batch = res.data;
          const vulnerabilities: ScanVulnerability[] = [];
          const tools: Record<string, any> = {};

          // --- MAPPING LOGIC (Adapted from BatchDetailModal) ---
          const validSeverities = ["Critical", "High", "Medium", "Low", "Info"];
          const normalizeSeverity = (sev: string): "Critical" | "High" | "Medium" | "Low" | "Info" => {
            if (!sev) return "Info";
            const titleCase = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
            if (validSeverities.includes(titleCase)) {
              return titleCase as "Critical" | "High" | "Medium" | "Low" | "Info";
            }
            return "Info";
          };

          const riskDetail = (batch as any).risk_details || batch.risk_detail || [];

          riskDetail.forEach((risk: any) => {
            let toolName = risk.scanner;
            if (toolName === "owasp-zap") toolName = "zap";
            tools[toolName] = true; // Mark tool as present

            // Flatten findings
            if (risk.findings && Array.isArray(risk.findings)) {
              risk.findings.forEach((finding: any) => {
                const isStringFinding = typeof finding === 'string';
                vulnerabilities.push({
                  id: `${toolName}-${Math.random().toString(36).substr(2, 9)}`,
                  tool: toolName as ToolKey,
                  severity: normalizeSeverity(isStringFinding ? risk.normalized_severity : (finding.severity || risk.normalized_severity)),
                  name: isStringFinding ? finding : (finding.name || finding.title || risk.description),
                  description: isStringFinding ? finding : (finding.description || risk.description),
                  affectedAsset: isStringFinding ? "N/A" : (finding.location || "N/A"),
                });
              });
            }
            // Summary vulnerability if no findings
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

          setSelectedScan({
            id: batch.batch_id,
            name: `Scan ${new Date(batch.created_at).toLocaleDateString()}`, // Generate name
            target: batch.target,
            status: batch.status,
            createdAt: batch.created_at,
            vulnerabilities,
            tools
          });
        }
      } catch (err) {
        console.error("Failed to fetch batch detail:", err);
      } finally {
        setLoadingPreview(false);
      }
    };
    fetchDetail();
  }, [selectedBatchId]);

  // Cleanup blob URL on unmount
  useEffect(() => {
    return () => {
      if (pdfBlobUrl) {
        URL.revokeObjectURL(pdfBlobUrl);
      }
    };
  }, [pdfBlobUrl]);

  const handleTogglePreview = async () => {
    if (showPreview) {
      setShowPreview(false);
      return;
    }

    if (!selectedBatchId) return;

    try {
      setIsPreviewLoading(true);
      setShowPreview(true);

      if (!pdfBlobUrl) {
        const res = await batchApi.preview(selectedBatchId);
        if (res.ok && res.data) {
          const url = URL.createObjectURL(res.data);
          setPdfBlobUrl(url);
        } else {
          console.error("Failed to fetch preview:", res.message);
          alert("Failed to load preview");
          setShowPreview(false);
        }
      }
    } catch (err) {
      console.error("Error fetching preview:", err);
      setShowPreview(false);
    } finally {
      setIsPreviewLoading(false);
    }
  };


  // Sort vulnerabilities by severity
  const sortedVulnerabilities = useMemo(() => {
    if (!selectedScan) return [];
    return [...selectedScan.vulnerabilities].sort((a, b) => {
      const severityA = SEVERITY_ORDER[a.severity.toLowerCase()] || 0;
      const severityB = SEVERITY_ORDER[b.severity.toLowerCase()] || 0;
      return vulnSortOrder === "desc" ? severityB - severityA : severityA - severityB;
    });
  }, [selectedScan, vulnSortOrder]);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const handleExport = async () => {
    if (!selectedBatchId || !selectedScan) return;

    try {
      setIsExporting(true);

      const res = await batchApi.report(selectedBatchId);

      if (!res.ok) {
        alert(`Failed to download report: ${res.message || "Unknown error"}`);
        return;
      }

      // Create blob from response
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);

      // Trigger download
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${selectedScan.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}-${formatDate(selectedScan.createdAt)}.pdf`;
      document.body.appendChild(a);
      a.click();

      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error("Export failed:", err);
      const message = err instanceof Error ? err.message : "Unknown error";
      alert(`Export failed: ${message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const getRiskColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'text-red-600 bg-red-50 dark:bg-red-900/20 dark:text-red-400 border-red-200 dark:border-red-800';
      case 'high': return 'text-orange-600 bg-orange-50 dark:bg-orange-900/20 dark:text-orange-400 border-orange-200 dark:border-orange-800';
      case 'medium': return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800';
      case 'low': return 'text-blue-600 bg-blue-50 dark:bg-blue-900/20 dark:text-blue-400 border-blue-200 dark:border-blue-800';
      default: return 'text-slate-600 bg-slate-50 dark:bg-slate-800 dark:text-slate-400 border-slate-200 dark:border-slate-700';
    }
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
        {/* Top Navigation */}
        <Header
          searchPlaceholder="Search reports..."
          searchValue={searchQuery}
          onSearch={setSearchQuery}
        />

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden px-8 py-10 md:px-12 md:py-12 scroll-smooth">
          <div className="max-w-7xl mx-auto flex flex-col gap-8 pb-20">
            {/* Page Header */}
            <div className="flex flex-col gap-2">
              <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                Export Reports
              </h2>
              <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                Select a scan to preview and export as PDF or HTML
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Left: Scan Selection */}
              <div className="lg:col-span-2">
                <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
                  <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/30">
                    <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                      Available Scans
                    </h3>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                      Select a scan to generate a report
                    </p>
                  </div>

                  <div className="divide-y divide-slate-200 dark:divide-slate-700 max-h-[600px] overflow-y-auto">
                    {loadingBatches ? (
                      <div className="p-8 text-center text-slate-500 flex flex-col items-center">
                        <span className="material-symbols-outlined animate-spin mb-2">sync</span>
                        Loading history...
                      </div>
                    ) : filteredBatches.length === 0 ? (
                      <div className="p-8 text-center text-slate-500">
                        {searchQuery ? "No reports found matching your search." : "No scan history found. Run a scan first"}
                      </div>
                    ) : (
                      filteredBatches.map((batch) => (
                        <div
                          key={batch.batch_id}
                          onClick={() => {
                            setSelectedBatchId(batch.batch_id);
                            setShowPreview(false);
                          }}
                          className={`p-4 cursor-pointer transition-all ${selectedBatchId === batch.batch_id
                            ? "bg-blue-50 dark:bg-blue-500/10 border-l-4 border-blue-500"
                            : "hover:bg-slate-50 dark:hover:bg-slate-700/20 border-l-4 border-transparent"
                            }`}>
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <h4 className="font-bold text-slate-900 dark:text-white">
                                {batch.target}
                              </h4>
                              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                                {formatDate(batch.timestamp)}
                              </p>
                              <div className="flex items-center gap-2 mt-2">
                                <span
                                  className={`px-2 py-1 rounded text-xs font-bold ${["completed", "finished", "success", "complete"].includes(batch.status.toLowerCase())
                                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
                                    : ["processing", "running", "scanning", "pending"].includes(batch.status.toLowerCase())
                                      ? "bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300"
                                      : "bg-slate-100 text-slate-700 dark:bg-slate-500/20 dark:text-slate-300"
                                    }`}>
                                  {batch.status}
                                </span>
                                {batch.risk_level && (
                                  <span className={`px-2 py-1 rounded text-xs font-bold border ${getRiskColor(batch.risk_level)}`}>
                                    {batch.risk_level} Risk
                                  </span>
                                )}
                              </div>
                            </div>
                            {selectedBatchId === batch.batch_id && (
                              <span className="material-symbols-outlined text-blue-600 dark:text-blue-400">
                                check_circle
                              </span>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Right: Preview & Export */}
              <div className="lg:col-span-1">
                <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm p-6 sticky top-6">
                  <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">
                    Export Options
                  </h3>

                  {!selectedBatchId ? (
                    <div className="text-center py-8 text-slate-500">
                      <span className="material-symbols-outlined text-4xl mb-2 block">
                        description
                      </span>
                      <p className="text-sm">Select a scan to export</p>
                    </div>
                  ) : loadingPreview ? (
                    <div className="text-center py-8 text-slate-500 flex flex-col items-center">
                      <span className="material-symbols-outlined animate-spin mb-2">sync</span>
                      <span>Loading details...</span>
                    </div>
                  ) : selectedScan ? (
                    <div className="flex flex-col gap-4">
                      {/* Format Selection */}
                      <div>
                        <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                          Export Format
                        </label>
                        <div className="w-full">
                          <button
                            onClick={() => setExportFormat("pdf")}
                            className={`w-full flex items-center justify-center gap-4 px-4 py-2 rounded-xl border-2 transition-all ${exportFormat === "pdf"
                              ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400"
                              : "border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600"
                              }`}>
                            <span className="material-symbols-outlined">picture_as_pdf</span>
                            <span className="font-bold text-sm">PDF</span>
                          </button>
                        </div>
                      </div>

                      {/* Preview Button */}
                      <button
                        onClick={handleTogglePreview}
                        disabled={isPreviewLoading}
                        className="w-full flex items-center justify-center gap-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-900 dark:text-white font-bold py-3 px-4 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                        {isPreviewLoading ? (
                          <span className="material-symbols-outlined animate-spin text-sm">sync</span>
                        ) : (
                          <span className="material-symbols-outlined">
                            {showPreview ? "visibility_off" : "visibility"}
                          </span>
                        )}
                        {isPreviewLoading ? "Loading..." : showPreview ? "Hide Preview" : "Show Preview"}
                      </button>

                      {/* Export Button */}
                      <button
                        onClick={handleExport}
                        disabled={isExporting}
                        className={`w-full flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3 px-4 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95 ${isExporting ? 'opacity-75 cursor-wait' : ''}`}>
                        {isExporting ? (
                          <span className="material-symbols-outlined animate-spin">sync</span>
                        ) : (
                          <span className="material-symbols-outlined">download</span>
                        )}
                        {isExporting ? 'Generating Report...' : 'Export Report'}
                      </button>

                      {/* Report Info */}
                      <div className="mt-4 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700">
                        <h4 className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase mb-2">
                          Report Details
                        </h4>
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span className="text-slate-600 dark:text-slate-400">
                              Target:
                            </span>
                            <span className="font-semibold text-slate-900 dark:text-white">
                              {selectedScan.target}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-600 dark:text-slate-400">
                              Vulnerabilities:
                            </span>
                            <span className="font-semibold text-slate-900 dark:text-white">
                              {selectedScan.vulnerabilities.length}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-600 dark:text-slate-400">
                              Format:
                            </span>
                            <span className="font-semibold text-slate-900 dark:text-white uppercase">
                              {exportFormat}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-red-500">Failed to load details</div>
                  )}
                </div>
              </div>
            </div>

            {/* Preview Section */}
            {showPreview && selectedScan && (
              <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm p-8 animate-fade-in">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
                    Report Preview
                  </h3>
                  <button
                    onClick={() => setShowPreview(false)}
                    className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>

                {/* Preview Content */}
                <div className="w-full h-[800px] bg-slate-100 dark:bg-slate-900 rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700">
                  {pdfBlobUrl ? (
                    <iframe
                      src={pdfBlobUrl}
                      className="w-full h-full"
                      title="Report Preview"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center text-slate-500">
                      <div className="flex flex-col items-center">
                        <span className="material-symbols-outlined text-4xl mb-2 animate-spin">sync</span>
                        <p>Loading PDF Preview...</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
