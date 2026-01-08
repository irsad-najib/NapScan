"use client";

import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { ToolKey } from "@/services/api";
import { useScan } from "@/context/ScanContext";
import { ToolList } from "@/components/scans/ToolList";

export default function ScansPage() {
  const router = useRouter();
  const { scans, startScan, deleteScan } = useScan();
  const [showNewScanForm, setShowNewScanForm] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // State for file upload
  const [dragActive, setDragActive] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  // State for expanding scan rows
  const [expandedScanId, setExpandedScanId] = useState<string | null>(null);

  // Helper to format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30";
      case "running":
        return "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30";
      case "failed":
        return "bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-500/30";
      default:
        return "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30";
    }
  };

  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    targetId: "",
    scanName: "",
    scanTiming: "now", // 'now' or 'scheduled'
    scheduledDate: "",
    scheduledTime: "",
    selectedTools: {
      nmap: false,
      zap: false,
      openvas: false,
      nuclei: false,
      sslyze: false,
      ffuf: false,
    },
  });


  const targets = [
    {
      id: 1,
      name: "api.company-prod.com",
      type: "Web Application",
      lastScanned: "Oct 20, 2023",
    },
    {
      id: 2,
      name: "192.168.10.55",
      type: "Network/Server",
      lastScanned: "Oct 21, 2023",
    },
    {
      id: 3,
      name: "staging.web.app",
      type: "Web Application",
      lastScanned: "Oct 22, 2023",
    },
    {
      id: 4,
      name: "api.internal.local",
      type: "API",
      lastScanned: "Oct 23, 2023",
    },
    {
      id: 5,
      name: "cms.ayolari.net",
      type: "Web Application",
      lastScanned: "Oct 24, 2023",
    },
  ];

  const handleStartScan = async () => {
    const target = String(selectedTarget ?? "").trim();
    if (!target) {
      alert("Please select a target");
      return;
    }

    const selectedTools = Object.entries(formData.selectedTools)
      .filter(([, selected]) => selected)
      .map(([tool]) => tool) as ToolKey[];

    if (selectedTools.length === 0) {
      alert("Please select at least one scanner tool");
      return;
    }

    setIsSubmitting(true);
    try {
      const scanId = await startScan(target, selectedTools, formData.scanName);
      setShowNewScanForm(false);
      // Removed redirect: router.push(`/scans/${scanId}`);
      // Expand the newly created scan
      setExpandedScanId(scanId);
    } catch (error) {
      console.error("Error creating scan:", error);
      alert("Failed to create scan. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleScanExpand = (scanId: string) => {
    setExpandedScanId(expandedScanId === scanId ? null : scanId);
  };

  const navItems = [
    { label: "Dashboard", icon: "dashboard", href: "/", active: false },
    { label: "Scans", icon: "radar", href: "/scans", active: true },
    { label: "Reports", icon: "description", href: "/reports", active: false },
    { label: "Settings", icon: "settings", href: "/settings", active: false },
  ];

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
              placeholder="Search scans..."
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

        {/* Main Content Scroll Area */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden px-8 py-10 md:px-12 md:py-12 scroll-smooth">
          <div className="max-w-7xl mx-auto flex flex-col gap-8 pb-20">
            {/* Breadcrumbs */}
            <div className="flex items-center gap-2 text-sm">
              <Link
                className="text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium"
                href="/">
                Home
              </Link>
              <span className="material-symbols-outlined text-slate-400 text-[18px]">
                chevron_right
              </span>
              <Link
                className="text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium"
                href="/scans">
                Scans
              </Link>
              {showNewScanForm && (
                <>
                  <span className="material-symbols-outlined text-slate-400 text-[18px]">
                    chevron_right
                  </span>
                  <span className="text-slate-900 dark:text-slate-100 font-semibold">
                    New Scan
                  </span>
                </>
              )}
            </div>

            {/* Page Header */}
            {!showNewScanForm && (
              <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
                <div className="flex flex-col gap-2">
                  <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                    Security Scans
                  </h2>
                  <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                    View and manage all security scans
                  </p>
                </div>
                <button
                  onClick={() => setShowNewScanForm(!showNewScanForm)}
                  className="flex items-center justify-center gap-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3.5 px-6 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95 shrink-0 h-12 whitespace-nowrap">
                  <span className="material-symbols-outlined text-lg">add</span>
                  <span>New Scan</span>
                </button>
              </div>
            )}
            {showNewScanForm && (
              <div className="flex flex-col gap-2">
                <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                  New Scan
                </h2>
              </div>
            )}

            {/* New Scan Form Modal */}
            {showNewScanForm && (
              <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-lg p-8 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-xl font-bold text-slate-900 dark:text-white">
                    Start New Security Scan
                  </h3>
                  <button
                    onClick={() => setShowNewScanForm(false)}
                    className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-colors">
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Select Target */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                      Target to Scan <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      list="targets-list"
                      value={selectedTarget || ""}
                      onChange={(e) => {
                        setSelectedTarget(e.target.value);
                      }}
                      placeholder="Type or select a target..."
                      className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    />

                    <datalist id="targets-list">
                      {targets.map((t) => (
                        <option key={t.id} value={t.name} />
                      ))}
                    </datalist>

                    {/* File Upload Section */}
                    <div className="mt-4">
                      <div
                        onDragOver={(e) => {
                          e.preventDefault();
                          setDragActive(true);
                        }}
                        onDragLeave={() => setDragActive(false)}
                        onDrop={(e) => {
                          e.preventDefault();
                          setDragActive(false);
                          const files = e.dataTransfer.files;
                          if (files.length > 0) {
                            setUploadedFile(files[0]);
                            setSelectedTarget(files[0].name);
                          }
                        }}
                        className={`flex items-center justify-center gap-3 px-6 py-4 rounded-xl border-2 border-dashed transition-all cursor-pointer ${dragActive
                          ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10"
                          : "border-slate-200 dark:border-slate-700 hover:border-blue-400 dark:hover:border-blue-600 bg-slate-50 dark:bg-slate-800/30 hover:bg-blue-50 dark:hover:bg-blue-500/5"
                          }`}
                        onClick={() => document.getElementById('file-upload')?.click()}
                      >
                        <span
                          className={`material-symbols-outlined text-2xl transition-colors ${dragActive
                            ? "text-blue-600 dark:text-blue-400"
                            : "text-slate-400"
                            }`}>
                          upload_file
                        </span>
                        <div className="text-left">
                          <p
                            className={`text-sm font-semibold ${dragActive
                              ? "text-blue-600 dark:text-blue-400"
                              : "text-slate-700 dark:text-slate-300"
                              }`}>
                            {uploadedFile ? uploadedFile.name : "Drop APK file here or click to browse"}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            Supports: APK files
                          </p>
                        </div>
                        {uploadedFile && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setUploadedFile(null);
                              if (selectedTarget === uploadedFile.name) {
                                setSelectedTarget(null);
                              }
                            }}
                            className="ml-auto text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                          >
                            <span className="material-symbols-outlined">close</span>
                          </button>
                        )}
                      </div>
                      <input
                        id="file-upload"
                        type="file"
                        accept=".apk"
                        className="hidden"
                        onChange={(e) => {
                          const files = e.target.files;
                          if (files && files.length > 0) {
                            setUploadedFile(files[0]);
                            setSelectedTarget(files[0].name);
                          }
                        }}
                      />
                    </div>
                  </div>

                  {/* Scanner Tools Selection */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-3">
                      Scanner Tools <span className="text-red-500">*</span>
                    </label>
                    <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                      {[
                        { id: "nmap", name: "Nmap", icon: "router" },
                        { id: "zap", name: "OWASP ZAP", icon: "bug_report" },
                        { id: "openvas", name: "OpenVAS", icon: "shield" },
                        { id: "nuclei", name: "Nuclei", icon: "bolt" },
                        { id: "sslyze", name: "SSLyze", icon: "lock" },
                        { id: "ffuf", name: "Ffuf", icon: "search" },
                      ].map((tool) => (
                        <label
                          key={tool.id}
                          className={`flex items-center gap-3 p-3 rounded-xl border-2 cursor-pointer transition-all ${formData.selectedTools[
                            tool.id as keyof typeof formData.selectedTools
                          ]
                            ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10"
                            : "border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600"
                            }`}>
                          <input
                            type="checkbox"
                            checked={
                              formData.selectedTools[
                              tool.id as keyof typeof formData.selectedTools
                              ]
                            }
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                selectedTools: {
                                  ...formData.selectedTools,
                                  [tool.id]: e.target.checked,
                                },
                              })
                            }
                            className="w-4 h-4 rounded border-slate-300 text-blue-600 cursor-pointer"
                          />
                          <div className="flex-1 text-center">
                            <span className="material-symbols-outlined text-lg block mb-1">
                              {tool.icon}
                            </span>
                            <span className="text-xs font-semibold text-slate-900 dark:text-white">
                              {tool.name}
                            </span>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Scan Timing */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-3">
                      Scan Timing <span className="text-red-500">*</span>
                    </label>
                    <div className="flex gap-4">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="scanTiming"
                          value="now"
                          checked={formData.scanTiming === "now"}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              scanTiming: e.target.value,
                            })
                          }
                          className="w-4 h-4 cursor-pointer"
                        />
                        <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                          Start Now
                        </span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="scanTiming"
                          value="scheduled"
                          checked={formData.scanTiming === "scheduled"}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              scanTiming: e.target.value,
                            })
                          }
                          className="w-4 h-4 cursor-pointer"
                        />
                        <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                          Schedule for Later
                        </span>
                      </label>
                    </div>
                  </div>

                  {/* Scheduled Date & Time */}
                  {formData.scanTiming === "scheduled" && (
                    <>
                      <div>
                        <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                          Date <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="date"
                          value={formData.scheduledDate}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              scheduledDate: e.target.value,
                            })
                          }
                          className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                          Time <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="time"
                          value={formData.scheduledTime}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              scheduledTime: e.target.value,
                            })
                          }
                          className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                        />
                      </div>
                    </>
                  )}

                  {/* Scan Name */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                      Scan Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={formData.scanName}
                      onChange={(e) =>
                        setFormData({ ...formData, scanName: e.target.value })
                      }
                      placeholder="e.g., Production API Security Check"
                      className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    />
                  </div>
                </div>

                {/* Selected Tools Summary */}
                {Object.values(formData.selectedTools).some((v) => v) && (
                  <div className="mt-6 p-4 bg-slate-100 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700">
                    <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-2">
                      Selected Scanners
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(formData.selectedTools)
                        .filter(([, selected]) => selected)
                        .map(([tool]) => {
                          const toolNames: Record<string, string> = {
                            nmap: "Nmap",
                            zap: "OWASP ZAP",
                            openvas: "OpenVAS",
                            nuclei: "Nuclei",
                            sslyze: "SSLyze",
                            ffuf: "Ffuf",
                          };
                          return (
                            <span
                              key={tool}
                              className="px-3 py-1.5 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-600">
                              {toolNames[tool]}
                            </span>
                          );
                        })}
                    </div>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex items-center gap-3 mt-8">
                  <button
                    onClick={handleStartScan}
                    disabled={isSubmitting}
                    className="flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-bold py-3 px-6 rounded-xl shadow-lg shadow-emerald-600/30 transition-all transform hover:scale-105 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed">
                    <span className="material-symbols-outlined text-lg">
                      {isSubmitting ? "hourglass_empty" : "play_arrow"}
                    </span>
                    <span>
                      {isSubmitting ? "Starting Scan..." : "Start Scan"}
                    </span>
                  </button>
                  <button
                    onClick={() => setShowNewScanForm(false)}
                    disabled={isSubmitting}
                    className="flex items-center justify-center gap-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white font-bold py-3 px-6 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                    <span>Cancel</span>
                  </button>
                </div>
              </div>
            )}

            {/* Table Section */}
            <div className="flex flex-col gap-5">
              {/* Table Container */}
              <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
                {/* Table */}
                <div className="overflow-x-auto w-full">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-100 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Scan Name
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Target
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Status
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Risk Level
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Vulns
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Date
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {scans.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="text-center py-8 text-slate-500">
                            No scans found. Start a new scan above.
                          </td>
                        </tr>
                      ) : (
                        scans.map((scan) => (
                          <>
                            <tr
                              key={scan.id}
                              className={`group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150 cursor-pointer ${expandedScanId === scan.id ? "bg-slate-50 dark:bg-slate-700/30" : ""
                                }`}
                              onClick={() => toggleScanExpand(scan.id)}
                            >
                              <td className="py-4 px-6">
                                <span className={`material-symbols-outlined text-slate-400 transition-transform ${expandedScanId === scan.id ? 'rotate-90' : ''}`}>
                                  chevron_right
                                </span>
                              </td>
                              <td className="py-4 px-6">
                                <p className="text-slate-900 dark:text-white font-semibold text-sm">
                                  {scan.name}
                                </p>
                              </td>
                              <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm">
                                {scan.target}
                              </td>
                              <td className="py-4 px-6 whitespace-nowrap">
                                <span
                                  className={`inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-bold capitalize ${getStatusColor(
                                    scan.status
                                  )}`}
                                >
                                  {scan.status}
                                </span>
                              </td>
                              <td className="py-4 px-6">
                                <span className="text-sm font-bold text-slate-500">
                                  - {/* Risk calculation not yet implemented */}
                                </span>
                              </td>
                              <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm font-mono font-bold">
                                {scan.vulnerabilities?.length || 0}
                              </td>
                              <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm">
                                {formatDate(scan.createdAt)}
                              </td>
                              <td className="py-4 px-6 text-right whitespace-nowrap">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    deleteScan(scan.id);
                                  }}
                                  className="text-slate-400 dark:text-slate-500 hover:text-red-600 dark:hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-700 p-2 rounded-lg transition-all"
                                >
                                  <span className="material-symbols-outlined text-[20px]">
                                    delete
                                  </span>
                                </button>
                              </td>
                            </tr>

                            {/* Expanded Row */}
                            {expandedScanId === scan.id && (
                              <tr className="bg-slate-50 dark:bg-slate-800/20">
                                <td colSpan={8} className="p-0">
                                  <div className="p-4 md:p-6 border-y border-slate-200 dark:border-slate-700">
                                    <div className="max-w-4xl mx-auto">
                                      <h4 className="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Scan Details & Tools</h4>
                                      <ToolList
                                        tools={scan.tools}
                                        target={scan.target}
                                        vulnerabilities={scan.vulnerabilities}
                                      />
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="bg-slate-100 dark:bg-slate-700/30 border-t border-slate-200 dark:border-slate-700 px-6 py-4 flex items-center justify-between">
                  <p className="text-sm text-slate-600 dark:text-slate-400 font-medium">
                    Showing{" "}
                    <span className="text-slate-900 dark:text-white font-bold">
                      {scans.length}
                    </span>{" "}
                    scans
                  </p>
                  <div className="flex items-center gap-2.5">
                    <button className="p-2 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed">
                      <span className="material-symbols-outlined">
                        chevron_left
                      </span>
                    </button>
                    <button className="p-2 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-all">
                      <span className="material-symbols-outlined">
                        chevron_right
                      </span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
