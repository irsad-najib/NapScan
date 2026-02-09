"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { useScan, ScanVulnerability } from "@/context/ScanContext";
import { Sidebar, Header } from "@/components/layout";
import { batchApi } from "@/services/api";

// Severity priority map (higher value = more severe)
const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

type SortOrder = "desc" | "asc";

export default function ReportsPage() {
  const { scans } = useScan();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [exportFormat, setExportFormat] = useState<"pdf" | "html">("pdf");
  const [vulnSortOrder, setVulnSortOrder] = useState<SortOrder>("desc");
  const [isExporting, setIsExporting] = useState(false);

  const selectedScan = scans.find(s => s.id === selectedScanId);

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
    if (!selectedScan) return;

    try {
      setIsExporting(true);

      if (!selectedScan.batchId) {
        alert("Report not available for this scan (missing batch ID). Please run a new scan.");
        setIsExporting(false);
        return;
      }

      const res = await batchApi.report(selectedScan.batchId);

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

  return (
    <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
        {/* Top Navigation */}
        <Header searchPlaceholder="Search reports..." />

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

                  <div className="divide-y divide-slate-200 dark:divide-slate-700">
                    {scans.length === 0 ? (
                      <div className="p-8 text-center text-slate-500">
                        No scans available. Run a scan first.
                      </div>
                    ) : (
                      scans.map((scan) => (
                        <div
                          key={scan.id}
                          onClick={() => {
                            setSelectedScanId(scan.id);
                            setShowPreview(false);
                          }}
                          className={`p-4 cursor-pointer transition-all ${selectedScanId === scan.id
                            ? "bg-blue-50 dark:bg-blue-500/10 border-l-4 border-blue-500"
                            : "hover:bg-slate-50 dark:hover:bg-slate-700/20"
                            }`}>
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <h4 className="font-bold text-slate-900 dark:text-white">
                                {scan.name}
                              </h4>
                              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                                {scan.target} • {formatDate(scan.createdAt)}
                              </p>
                              <div className="flex items-center gap-2 mt-2">
                                <span
                                  className={`px-2 py-1 rounded text-xs font-bold ${scan.status === "completed"
                                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300"
                                    : scan.status === "running"
                                      ? "bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300"
                                      : "bg-slate-100 text-slate-700 dark:bg-slate-500/20 dark:text-slate-300"
                                    }`}>
                                  {scan.status}
                                </span>
                                <span className="text-xs text-slate-500">
                                  {scan.vulnerabilities.length} vulnerabilities
                                </span>
                              </div>
                            </div>
                            {selectedScanId === scan.id && (
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

                  {!selectedScan ? (
                    <div className="text-center py-8 text-slate-500">
                      <span className="material-symbols-outlined text-4xl mb-2 block">
                        description
                      </span>
                      <p className="text-sm">Select a scan to export</p>
                    </div>
                  ) : (
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
                        onClick={() => setShowPreview(!showPreview)}
                        className="w-full flex items-center justify-center gap-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-900 dark:text-white font-bold py-3 px-4 rounded-xl transition-all">
                        <span className="material-symbols-outlined">
                          {showPreview ? "visibility_off" : "visibility"}
                        </span>
                        {showPreview ? "Hide Preview" : "Show Preview"}
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
                              Scan:
                            </span>
                            <span className="font-semibold text-slate-900 dark:text-white">
                              {selectedScan.name}
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
                <div className="prose dark:prose-invert max-w-none">
                  <h1>{selectedScan.name}</h1>
                  <p className="text-slate-600 dark:text-slate-400">
                    Target: {selectedScan.target} | Date: {formatDate(selectedScan.createdAt)}
                  </p>

                  <h2>Executive Summary</h2>
                  <p>
                    This security scan was conducted on {formatDate(selectedScan.createdAt)} targeting{" "}
                    <strong>{selectedScan.target}</strong>. The scan identified{" "}
                    <strong>{selectedScan.vulnerabilities.length}</strong> potential security issues.
                  </p>

                  <h2>Scan Tools Used</h2>
                  <ul>
                    {Object.keys(selectedScan.tools).map((tool) => (
                      <li key={tool}>{tool.toUpperCase()}</li>
                    ))}
                  </ul>

                  <div className="flex items-center justify-between mt-8 mb-4">
                    <h2 className="m-0">Vulnerabilities Found</h2>
                    <button
                      onClick={() => setVulnSortOrder(vulnSortOrder === "desc" ? "asc" : "desc")}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
                      title={vulnSortOrder === "desc" ? "Showing: Highest severity first" : "Showing: Lowest severity first"}
                    >
                      <span className="material-symbols-outlined text-sm">
                        {vulnSortOrder === "desc" ? "arrow_downward" : "arrow_upward"}
                      </span>
                      <span>Severity {vulnSortOrder === "desc" ? "↓" : "↑"}</span>
                    </button>
                  </div>
                  {sortedVulnerabilities.length === 0 ? (
                    <p>No vulnerabilities detected.</p>
                  ) : (
                    <div className="space-y-4">
                      {sortedVulnerabilities.map((vuln) => (
                        <div
                          key={vuln.id}
                          className="p-4 border border-slate-200 dark:border-slate-700 rounded-lg">
                          <h3 className="text-lg font-bold">{vuln.name}</h3>
                          <p className="text-sm">
                            <strong>Severity:</strong> {vuln.severity}
                          </p>
                          <p className="text-sm">
                            <strong>Tool:</strong> {vuln.tool}
                          </p>
                          <p className="mt-2">{vuln.description}</p>
                        </div>
                      ))}
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
