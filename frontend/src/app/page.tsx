"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { request, batchApi, BatchItem } from "@/services/api";
import { Sidebar, Header } from "@/components/layout";
import { BatchDetailModal } from "@/components/scans/BatchDetailModal";
import { useRouter } from "next/navigation";

export default function Home() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All Statuses");
  const [batches, setBatches] = useState<BatchItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedBatchId, setSelectedBatchId] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const fetchBatches = async () => {
      try {
        const response = await batchApi.list();
        if (response.ok && response.data) {
          setBatches(response.data);
        }
      } catch (error) {
        console.error("Failed to fetch batch list:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchBatches();
    const interval = setInterval(fetchBatches, 15000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  // Calculate stats dynamically
  const totalTargets = new Set(batches.map((b) => b.target)).size;
  const activeScans = batches.filter((b) =>
    ["processing", "running", "scanning", "pending"].includes(b.status.toLowerCase())
  ).length;
  const criticalRisks = batches.filter((b) =>
    ["critical", "high"].includes((b.risk_level || "").toLowerCase())
  ).length;
  const completedScans = batches.filter((b) =>
    ["completed", "finished", "success", "complete"].includes(b.status.toLowerCase())
  ).length;
  const successRate = batches.length > 0 ? Math.round((completedScans / batches.length) * 100) : 0;

  const stats = [
    {
      label: "Total Targets",
      value: totalTargets.toString(),
      trend: batches.length > 0 ? "Tracked" : "No Data", // Simplified trend
      trendUp: true,
      icon: "target",
      bgColor: "bg-gradient-to-br from-blue-600 to-blue-400",
      borderColor: "border-blue-500/30",
      iconColor: "text-blue-100",
    },
    {
      label: "Active Scans",
      value: activeScans.toString(),
      trend: activeScans > 0 ? "Running" : "Idle",
      trendUp: activeScans > 0,
      icon: "radar",
      bgColor: "bg-gradient-to-br from-cyan-600 to-cyan-400",
      borderColor: "border-cyan-500/30",
      iconColor: "text-cyan-100",
    },
    {
      label: "Critical/High Risks",
      value: criticalRisks.toString(),
      trend: criticalRisks > 0 ? "Action Needed" : "Secure",
      trendUp: criticalRisks === 0, // Green if 0
      icon: "warning",
      bgColor: "bg-gradient-to-br from-red-600 to-red-400",
      borderColor: "border-red-500/30",
      iconColor: "text-red-100",
    },
    {
      label: "Success Rate",
      value: `${successRate}%`,
      trend: "Completion",
      trendUp: successRate >= 50,
      icon: "check_circle",
      bgColor: "bg-gradient-to-br from-emerald-600 to-emerald-400",
      borderColor: "border-emerald-500/30",
      iconColor: "text-emerald-100",
    },
  ];

  const getStatusBadgeColor = (status: string) => {
    switch (status.toLowerCase()) {
      case "processing":
      case "running":
      case "scanning":
        return "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30";
      case "completed":
      case "complete":
      case "success":
      case "finished":
        return "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30";
      case "idle":
        return "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30";
      case "scheduled":
        return "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30";
      case "failed":
        return "bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-red-200 dark:border-red-500/30";
      default:
        return "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30";
    }
  };

  const filteredBatches = batches.filter(batch => {
    // 1. Status Filter
    let satisfiesStatus = true;
    if (statusFilter !== "All Statuses") {
      const status = batch.status.toLowerCase();
      if (statusFilter === "Processing") {
        satisfiesStatus = ["processing", "running", "scanning", "pending"].includes(status);
      } else if (statusFilter === "Completed") {
        satisfiesStatus = ["completed", "finished", "success", "complete"].includes(status);
      } else if (statusFilter === "Failed") {
        satisfiesStatus = status === "failed";
      }
    }

    // 2. Search Filter
    const satisfiesSearch = !searchQuery ||
      batch.target.toLowerCase().includes(searchQuery.toLowerCase());

    return satisfiesStatus && satisfiesSearch;
  });

  const getRiskColor = (riskLevel: string | null) => {
    if (!riskLevel) return "text-slate-600 dark:text-slate-400";
    switch (riskLevel.toLowerCase()) {
      case "high":
      case "critical":
        return "text-rose-600 dark:text-rose-400";
      case "medium":
        return "text-amber-600 dark:text-amber-400";
      case "low":
        return "text-emerald-600 dark:text-emerald-400";
      default:
        return "text-slate-600 dark:text-slate-400";
    }
  };

  // Calculate risk level from score if not provided by API
  const getRiskLevel = (riskLevel: string | null | undefined, riskScore: number): string => {
    if (riskLevel) return riskLevel;
    if (riskScore >= 500) return "CRITICAL";
    if (riskScore >= 100) return "HIGH";
    if (riskScore >= 50) return "MEDIUM";
    if (riskScore > 0) return "LOW";
    return "INFO";
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
        {/* Top Navigation */}
        <Header
          searchPlaceholder="Search targets..."
          searchValue={searchQuery}
          onSearch={setSearchQuery}
        />

        {/* Main Content Scroll Area */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden px-8 py-10 md:px-12 md:py-12 scroll-smooth">
          <div className="max-w-7xl mx-auto flex flex-col gap-8 pb-20">
            {/* Page Header */}
            <div className="flex flex-col gap-2">
              <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                Security Overview
              </h2>
              <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                Monitor and manage your attack surface
              </p>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 p-6 shadow-sm hover:shadow-md transition-all group">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <p className="text-slate-600 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">
                        {stat.label}
                      </p>
                      <p className="text-slate-900 dark:text-white text-2xl font-bold mt-1">
                        {stat.value}
                      </p>
                    </div>
                    <div
                      className={`p-3 rounded-xl ${stat.bgColor} group-hover:scale-110 transition-transform`}>
                      <span
                        className={`material-symbols-outlined text-2xl ${stat.iconColor}`}>
                        {stat.icon}
                      </span>
                    </div>
                  </div>
                  <div
                    className={`flex items-center gap-2 text-sm font-semibold ${stat.trendUp
                      ? "text-emerald-600 dark:text-emerald-400"
                      : "text-red-600 dark:text-red-400"
                      }`}>
                    <span className="material-symbols-outlined text-base">
                      {stat.trendUp ? "trending_up" : "trending_down"}
                    </span>
                    <span>{stat.trend}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Targets Table Section */}
            <div className="flex flex-col gap-5">
              {/* Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-4">
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
                  Results
                </h3>
                <div className="flex items-center gap-3">
                  <div className="relative group">
                    <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 text-[20px] group-focus-within:text-blue-500 transition-colors pointer-events-none">
                      filter_list
                    </span>
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="h-10 pl-10 pr-9 bg-white dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 rounded-xl text-sm text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 dark:focus:border-blue-400 outline-none cursor-pointer appearance-none font-medium transition-all hover:border-slate-400 dark:hover:border-slate-600">
                      <option>All Statuses</option>
                      <option>Processing</option>
                      <option>Completed</option>
                      <option>Failed</option>
                    </select>
                    <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-slate-400">
                      <span className="material-symbols-outlined text-sm">
                        expand_more
                      </span>
                    </span>
                  </div>
                  <button
                    onClick={() => router.push("/reports")}
                    className="h-10 px-4 bg-white dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 rounded-xl text-sm text-slate-700 dark:text-slate-200 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 transition-all flex items-center gap-2 font-medium">
                    <span className="material-symbols-outlined text-[18px]">
                      download
                    </span>
                    <span>Export</span>
                  </button>
                </div>
              </div>

              {/* Table Container */}
              <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-100 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Target
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Status
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Risk Score
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">
                          Date Initiated
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {loading ? (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-slate-500 dark:text-slate-400">
                            Loading batches...
                          </td>
                        </tr>
                      ) : filteredBatches.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-slate-500 dark:text-slate-400">
                            No scans found matching your filter.
                          </td>
                        </tr>
                      ) : (
                        filteredBatches.map((batch) => (
                          <tr
                            key={batch.batch_id}
                            className="group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150">
                            <td className="py-4 px-6">
                              <div className="flex items-center gap-3">
                                <div className="bg-gradient-to-br from-blue-100 dark:from-blue-500/20 to-cyan-100 dark:to-cyan-500/20 p-2.5 rounded-lg text-blue-600 dark:text-blue-400">
                                  <span className="material-symbols-outlined text-[20px]">
                                    dns
                                  </span>
                                </div>
                                <div>
                                  <p className="text-sm font-bold text-slate-900 dark:text-white">
                                    {batch.target || "Unknown Target"}
                                  </p>
                                  {/* <p className="text-xs text-slate-500 dark:text-slate-400 font-mono"> */}
                                  {/* {batch.batch_id.substring(0, 8)}... */}
                                  {/* </p> */}
                                </div>
                              </div>
                            </td>
                            <td className="py-4 px-6">
                              <span
                                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border ${getStatusBadgeColor(
                                  batch.status
                                )}`}>
                                {batch.status === "processing" && (
                                  <span className="relative flex h-2 w-2">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
                                  </span>
                                )}
                                <span className="capitalize">{batch.status}</span>
                              </span>
                            </td>
                            <td className="py-4 px-6">
                              <div className="flex items-center gap-2">
                                <span
                                  className={`text-sm font-bold ${getRiskColor(
                                    getRiskLevel(batch.risk_level, batch.risk_score)
                                  )}`}>
                                  {getRiskLevel(batch.risk_level, batch.risk_score)}
                                </span>
                                <span
                                  className={`px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300`}>
                                  {batch.risk_score}
                                </span>
                              </div>
                            </td>
                            <td className="py-4 px-6">
                              <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">
                                {new Date(batch.timestamp).toLocaleDateString()}
                              </p>
                              <p className="text-xs text-slate-500 dark:text-slate-400">
                                {new Date(batch.timestamp).toLocaleTimeString()}
                              </p>
                            </td>
                            <td className="py-4 px-6 text-right">
                              <button
                                onClick={() => setSelectedBatchId(batch.batch_id)}
                                className="text-slate-400 dark:text-slate-500 hover:text-white dark:hover:text-white hover:bg-blue-600 p-2 rounded-lg transition-all transform hover:scale-110 mr-2">
                                <span className="material-symbols-outlined text-[22px]">
                                  visibility
                                </span>
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="bg-slate-100 dark:bg-slate-700/30 border-t border-slate-200 dark:border-slate-700 px-6 py-4 flex items-center justify-between">
                  <p className="text-sm text-slate-600 dark:text-slate-400 font-medium">
                    Showing {filteredBatches.length} entries
                  </p>
                  <div className="flex items-center gap-2.5">
                    <button
                      disabled
                      className="px-4 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed font-medium transition-all">
                      Previous
                    </button>
                    <button className="px-4 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 font-medium transition-all">
                      Next
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>

      {selectedBatchId && (
        <BatchDetailModal
          batchId={selectedBatchId}
          onClose={() => setSelectedBatchId(null)}
        />
      )}
    </div>
  );
}
