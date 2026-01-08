"use client";

import { useState } from "react";
import Link from "next/link";
import { request } from "@/services/api";

export default function Home() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All Statuses");

  const handleHealthCheck = async () => {
    const res = await request<{ status?: string }>({
      method: "GET",
      url: "/health",
    });

    if (!res.ok) {
      const details = res.details ? `\n\n${res.details}` : "";
      alert(`Health check failed: ${res.message}${details}`);
      return;
    }

    alert("API Health: " + (res.data?.status ?? "ok"));
  };

  const targets = [
    {
      id: 1,
      name: "api.company-prod.com",
      description: "Production API Gateway",
      icon: "language",
      status: "Scanning (45%)",
      statusType: "scanning",
      riskScore: "Analyzing...",
      riskLevel: null,
      vulnCount: null,
      lastScanned: "Just now",
    },
    {
      id: 2,
      name: "192.168.10.55",
      description: "Internal Database",
      icon: "dns",
      status: "Completed",
      statusType: "completed",
      riskScore: "8.5",
      riskLevel: "High",
      vulnCount: "3 Critical, 5 High",
      lastScanned: "2 hours ago",
    },
    {
      id: 3,
      name: "staging.web.app",
      description: "Staging Environment",
      icon: "language",
      status: "Idle",
      statusType: "idle",
      riskScore: "2.1",
      riskLevel: "Low",
      vulnCount: "0 Critical, 0 High",
      lastScanned: "Oct 24, 2023",
    },
    {
      id: 4,
      name: "aws-s3-backup-bucket",
      description: "Cloud Storage",
      icon: "cloud_queue",
      status: "Scheduled",
      statusType: "scheduled",
      riskScore: "Pending scan...",
      riskLevel: null,
      vulnCount: null,
      lastScanned: "Never",
    },
  ];

  const stats = [
    {
      label: "Total Targets",
      value: "124",
      trend: "+5%",
      trendUp: true,
      icon: "target",
      bgColor: "bg-gradient-to-br from-blue-600 to-blue-400",
      borderColor: "border-blue-500/30",
      iconColor: "text-black-400",
    },
    {
      label: "Active Scans",
      value: "3",
      trend: "Running",
      trendUp: true,
      icon: "radar",
      bgColor: "bg-gradient-to-br from-cyan-600 to-cyan-400",
      borderColor: "border-cyan-500/30",
      iconColor: "text-black-400",
    },
    {
      label: "Critical Vulns",
      value: "12",
      trend: "+5%",
      trendUp: true,
      icon: "warning",
      bgColor: "bg-gradient-to-br from-red-600 to-red-400",
      borderColor: "border-red-500/30",
      iconColor: "text-black-400",
    },
    {
      label: "Remediation Rate",
      value: "85%",
      trend: "+12%",
      trendUp: true,
      icon: "check_circle",
      bgColor: "bg-gradient-to-br from-emerald-600 to-emerald-400",
      borderColor: "border-emerald-500/30",
      iconColor: "text-black-400",
    },
  ];

  const navItems = [
    { label: "Dashboard", icon: "dashboard", active: true, href: "/" },
    { label: "Scans", icon: "radar", active: false, href: "/scans" },
    { label: "Reports", icon: "description", active: false, href: "/reports" },
    { label: "Settings", icon: "settings", active: false, href: "/settings" },
  ];

  const getStatusBadgeColor = (statusType: string) => {
    switch (statusType) {
      case "scanning":
        return "bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30";
      case "completed":
        return "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30";
      case "idle":
        return "bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30";
      case "scheduled":
        return "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/30";
      default:
        return "";
    }
  };

  const getRiskColor = (riskLevel: string | null) => {
    switch (riskLevel) {
      case "High":
        return "text-rose-600 dark:text-rose-400";
      case "Low":
        return "text-emerald-600 dark:text-emerald-400";
      default:
        return "text-slate-600 dark:text-slate-400";
    }
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
              <button
                onClick={handleHealthCheck}
                className="mt-4 w-full bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-300 hover:bg-green-200 dark:hover:bg-green-500/30 font-semibold text-sm px-4 py-3 rounded-xl transition-colors flex items-center justify-center gap-2">
                test health
              </button>
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
              placeholder="Search targets..."
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
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
                  All Targets
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
                      <option>Scanning</option>
                      <option>Completed</option>
                      <option>Idle</option>
                      <option>Scheduled</option>
                    </select>
                    <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-slate-400">
                      <span className="material-symbols-outlined text-sm">
                        expand_more
                      </span>
                    </span>
                  </div>
                  <button className="h-10 px-4 bg-white dark:bg-slate-800/50 border border-slate-300 dark:border-slate-700 rounded-xl text-sm text-slate-700 dark:text-slate-200 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 transition-all flex items-center gap-2 font-medium">
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
                          Last Scanned
                        </th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {targets.map((target) => (
                        <tr
                          key={target.id}
                          className="group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150">
                          <td className="py-4 px-6">
                            <div className="flex items-center gap-3">
                              <div className="bg-gradient-to-br from-blue-100 dark:from-blue-500/20 to-cyan-100 dark:to-cyan-500/20 p-2.5 rounded-lg text-blue-600 dark:text-blue-400">
                                <span className="material-symbols-outlined text-[20px]">
                                  {target.icon}
                                </span>
                              </div>
                              <div>
                                <p className="text-sm font-bold text-slate-900 dark:text-white">
                                  {target.name}
                                </p>
                                <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">
                                  {target.description}
                                </p>
                              </div>
                            </div>
                          </td>
                          <td className="py-4 px-6">
                            <span
                              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border ${getStatusBadgeColor(
                                target.statusType
                              )}`}>
                              {target.statusType === "scanning" && (
                                <span className="relative flex h-2 w-2">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
                                </span>
                              )}
                              {target.statusType === "completed" && (
                                <span className="material-symbols-outlined text-[16px]">
                                  check_circle
                                </span>
                              )}
                              {target.statusType === "idle" && (
                                <span className="material-symbols-outlined text-[16px]">
                                  pause_circle
                                </span>
                              )}
                              {target.statusType === "scheduled" && (
                                <span className="material-symbols-outlined text-[16px]">
                                  schedule
                                </span>
                              )}
                              {target.status}
                            </span>
                          </td>
                          <td className="py-4 px-6">
                            {target.statusType === "scanning" ? (
                              <div className="flex items-center gap-2">
                                <div className="w-24 h-2.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                                  <div className="h-full bg-gradient-to-r from-blue-400 to-cyan-400 animate-pulse w-1/2"></div>
                                </div>
                                <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">
                                  Analyzing...
                                </span>
                              </div>
                            ) : target.statusType === "scheduled" ? (
                              <span className="text-sm text-slate-400 dark:text-slate-500 italic">
                                Pending scan...
                              </span>
                            ) : (
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-2">
                                  <span
                                    className={`text-sm font-bold ${getRiskColor(
                                      target.riskLevel
                                    )}`}>
                                    {target.riskLevel}
                                  </span>
                                  <span
                                    className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${target.riskLevel === "High"
                                        ? "bg-rose-100 dark:bg-rose-500/20 text-rose-700 dark:text-rose-400"
                                        : "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400"
                                      }`}>
                                    {target.riskScore}
                                  </span>
                                </div>
                                <p className="text-[10px] text-slate-500 dark:text-slate-400 font-medium">
                                  {target.vulnCount}
                                </p>
                              </div>
                            )}
                          </td>
                          <td className="py-4 px-6">
                            <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">
                              {target.lastScanned}
                            </p>
                          </td>
                          <td className="py-4 px-6 text-right">
                            {target.statusType === "scanning" ? (
                              <button className="text-slate-400 dark:text-slate-500 hover:text-white dark:hover:text-white hover:bg-red-500 dark:hover:bg-red-600/80 p-2 rounded-lg transition-all transform hover:scale-110">
                                <span className="material-symbols-outlined text-[22px]">
                                  stop_circle
                                </span>
                              </button>
                            ) : (
                              <>
                                <button className="text-slate-400 dark:text-slate-500 hover:text-white dark:hover:text-white hover:bg-blue-600 p-2 rounded-lg transition-all transform hover:scale-110 mr-2">
                                  <span className="material-symbols-outlined text-[22px]">
                                    play_arrow
                                  </span>
                                </button>
                                <button className="text-slate-400 dark:text-slate-500 hover:text-white dark:hover:text-white hover:bg-slate-700 dark:hover:bg-slate-600 p-2 rounded-lg transition-all transform hover:scale-110">
                                  <span className="material-symbols-outlined text-[22px]">
                                    more_vert
                                  </span>
                                </button>
                              </>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="bg-slate-100 dark:bg-slate-700/30 border-t border-slate-200 dark:border-slate-700 px-6 py-4 flex items-center justify-between">
                  <p className="text-sm text-slate-600 dark:text-slate-400 font-medium">
                    Showing 1 to 4 of 124 entries
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
    </div>
  );
}
