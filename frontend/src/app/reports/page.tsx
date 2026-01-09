"use client";

import { useState } from "react";
import Link from "next/link";
import { useScan } from "@/context/ScanContext";

export default function ReportsPage() {
  const { scans } = useScan();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [exportFormat, setExportFormat] = useState<"pdf" | "html">("pdf");

  const selectedScan = scans.find(s => s.id === selectedScanId);

  const navItems = [
    { label: "Dashboard", icon: "dashboard", href: "/" },
    { label: "Scans", icon: "radar", href: "/scans" },
    { label: "Reports", icon: "description", href: "/reports", active: true },
    { label: "Settings", icon: "settings", href: "/settings" },
  ];

  const handleExport = () => {
    if (!selectedScan) return;

    // Simulate export
    alert(`Exporting "${selectedScan.name}" as ${exportFormat.toUpperCase()}...`);
    // In real implementation, this would call an API to generate the report
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
      {/* Sidebar */}
      <aside className="w-64 bg-white dark:bg-slate-900 border-r-2 border-slate-200 dark:border-slate-800 flex-col hidden md:flex shrink-0 transition-all duration-300">
        <div className="h-full flex flex-col justify-between p-6">
          <div className="flex flex-col gap-8">
            {/* Logo */}
            <div className="flex items-center gap-3 px-2">
              <div className="bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center aspect-square rounded-lg size-11 text-white shadow-lg shadow-blue-500/20">
                <span className="material-symbols-outlined text-xl font-bold">
                  shield_lock
                </span>
              </div>
              <div className="flex flex-col">
                <h1 className="text-slate-900 dark:text-white text-base font-bold leading-tight">
                  NapScan
                </h1>
                <p className="text-slate-500 dark:text-slate-400 text-xs">
                  Security
                </p>
              </div>
            </div>

            {/* Nav Items */}
            <nav className="flex flex-col gap-2">
              {navItems.map((item) => (
                <Link
                  key={item.label}
                  href={item.href}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${item.active
                      ? "bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/20"
                      : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200"
                    }`}>
                  <span
                    className={`material-symbols-outlined text-xl transition-transform ${item.active
                        ? "fill-current scale-110"
                        : "group-hover:scale-110"
                      }`}>
                    {item.icon}
                  </span>
                  <span
                    className={`text-sm font-semibold tracking-wide ${item.active
                        ? "text-white"
                        : "text-slate-700 dark:text-slate-300"
                      }`}>
                    {item.label}
                  </span>
                </Link>
              ))}
            </nav>
          </div>

          {/* User Profile Bottom */}
          <div className="flex items-center gap-3 px-4 py-4 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer border-t border-slate-200 dark:border-slate-800 pt-5 transition-colors">
            <div
              className="bg-center bg-no-repeat bg-cover rounded-lg size-9 shrink-0 ring-2 ring-blue-500/20"
              style={{
                backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuCh8uYRP-HT-F-XERcS5Eey8codaekqO8OB2xh0uUpbbudDU-w4poJggQ538EII8_qWXNp9iiyhXdDmfvAFNQ_Ltqpn0_ri0HezeEd7kMC8x_Fh_-u_SZv0CWyIVLh5PKGuQbhdq8cFikywQ0HXMRN1VgQ6oyQXarl8BpM2_kF72N_hlRRja1UW2llExWmJLu0bhPiU2qzRO5BxFCB7bx3baPcDNCVQeLdn2NI3ftYREJ9mOBGbZJ-FW_qnKINaOaiRIo2sAQazNTqt")`,
              }}
            />
            <div className="flex flex-col min-w-0 flex-1">
              <p className="text-slate-900 dark:text-white text-sm font-semibold truncate">
                Alex Morgan
              </p>
              <p className="text-slate-500 dark:text-slate-500 text-xs truncate">
                Security Analyst
              </p>
            </div>
            <span className="material-symbols-outlined text-slate-600 dark:text-slate-400 text-lg">
              expand_more
            </span>
          </div>
        </div>
      </aside>

      {/* Main Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
        {/* Top Navigation */}
        <header className="h-16 flex items-center justify-between px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 backdrop-blur-sm shrink-0 z-10">
          <button className="md:hidden text-slate-600 dark:text-slate-400 hover:text-blue-500 transition-colors">
            <span className="material-symbols-outlined">menu</span>
          </button>

          {/* Search */}
          <div className="hidden md:flex items-center bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 px-4 py-2 w-72 focus-within:ring-2 focus-within:ring-blue-500/50 focus-within:border-transparent transition-all hover:border-slate-300 dark:hover:border-slate-600">
            <span className="material-symbols-outlined text-slate-400 text-[20px]">
              search
            </span>
            <input
              className="bg-transparent border-none text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-400 focus:ring-0 w-full ml-3 h-6 font-medium"
              placeholder="Search reports..."
              type="text"
            />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-5 ml-auto">
            <button className="relative p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
              <span className="material-symbols-outlined text-xl">
                notifications
              </span>
              <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border-2 border-white dark:border-slate-950 shadow-md"></span>
            </button>
            <button className="p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
              <span className="material-symbols-outlined text-xl">help</span>
            </button>
            <div className="h-6 w-px bg-slate-200 dark:bg-slate-700"></div>
            <button className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:text-blue-600 dark:hover:text-blue-400 transition-colors px-3 py-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800">
              <span>Docs</span>
              <span className="material-symbols-outlined text-lg">
                open_in_new
              </span>
            </button>
          </div>
        </header>

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
                        <div className="grid grid-cols-2 gap-2">
                          <button
                            onClick={() => setExportFormat("pdf")}
                            className={`flex items-center justify-center gap-2 px-4 py-3 rounded-xl border-2 transition-all ${exportFormat === "pdf"
                                ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400"
                                : "border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600"
                              }`}>
                            <span className="material-symbols-outlined">
                              picture_as_pdf
                            </span>
                            <span className="font-bold text-sm">PDF</span>
                          </button>
                          <button
                            onClick={() => setExportFormat("html")}
                            className={`flex items-center justify-center gap-2 px-4 py-3 rounded-xl border-2 transition-all ${exportFormat === "html"
                                ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400"
                                : "border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600"
                              }`}>
                            <span className="material-symbols-outlined">
                              code
                            </span>
                            <span className="font-bold text-sm">HTML</span>
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
                        className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3 px-4 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95">
                        <span className="material-symbols-outlined">
                          download
                        </span>
                        Export Report
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

                  <h2>Vulnerabilities Found</h2>
                  {selectedScan.vulnerabilities.length === 0 ? (
                    <p>No vulnerabilities detected.</p>
                  ) : (
                    <div className="space-y-4">
                      {selectedScan.vulnerabilities.map((vuln) => (
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
