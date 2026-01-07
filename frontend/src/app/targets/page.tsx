"use client";

import { useState } from "react";
import Link from "next/link";

export default function TargetsPage() {
  const [newTarget, setNewTarget] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const [statusFilter, setStatusFilter] = useState("All Statuses");

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
      icon: "target",
      color: "primary",
    },
    {
      label: "Active Scans",
      value: "3",
      trend: "Running",
      icon: "radar",
      color: "blue",
      isBadge: true,
    },
    {
      label: "Critical Vulns",
      value: "12",
      trend: "Action Needed",
      icon: "bug_report",
      color: "rose",
      isBadge: true,
    },
  ];

  const navItems = [
    { label: "Dashboard", icon: "dashboard", active: false, href: "/" },
    { label: "Targets", icon: "target", active: true, href: "/targets" },
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
                  NapScan Pro
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
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
                    item.active
                      ? "bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/20"
                      : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200"
                  }`}>
                  <span
                    className={`material-symbols-outlined text-xl transition-transform ${
                      item.active
                        ? "fill-current scale-110"
                        : "group-hover:scale-110"
                    }`}>
                    {item.icon}
                  </span>
                  <span
                    className={`text-sm font-semibold tracking-wide ${
                      item.active
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
                backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuDa-VFRgn-smOSZhtUDbo1krQ-J-XX2bem17WBb9WUWciw7f38zXecG-ItvEW9FavSzaPwp9U7g_FCmEoXlrtTM98e3M0h1mAOtQNR_f4PCvcOa__Jv3M6TNt8wkb0dsbpIOddCl6KobOqzpM6kYrBZrrc6lzXi30KO4WHVBEt2_D6czQf1VyRIgQQsx5aPyEg90XF-EhJBH6NUCQbbIEW4oRD20yMIF1R0VxE0Jo1StIAmE1SfzZ7w3DApWJDBW2_Ry5UaQ3MgvULG")`,
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
            />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-5 ml-auto">
            <button className="relative p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
              <span className="material-symbols-outlined text-xl">
                notifications
              </span>
              <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border-2 border-white dark:border-slate-900 shadow-md"></span>
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
          <div className="max-w-7xl mx-auto flex flex-col gap-10 pb-20">
            {/* Breadcrumbs */}
            <div className="flex items-center gap-2 text-sm">
              <a
                className="text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium"
                href="#">
                Home
              </a>
              <span className="material-symbols-outlined text-slate-400 text-[18px]">
                chevron_right
              </span>
              <span className="text-slate-900 dark:text-slate-100 font-semibold">
                Targets
              </span>
            </div>

            {/* Page Header */}
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
              <div className="flex flex-col gap-2">
                <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                  Target Management
                </h2>
                <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                  Manage your attack surface by adding domains or IPs for
                  automated scanning.
                </p>
              </div>
              <button className="flex items-center justify-center gap-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3.5 px-6 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95 shrink-0 h-12 whitespace-nowrap">
                <span className="material-symbols-outlined text-lg">bolt</span>
                <span>Quick Scan</span>
              </button>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="bg-white dark:bg-slate-800/50 rounded-2xl p-6 border border-slate-200 dark:border-slate-700 shadow-sm hover:shadow-md dark:hover:shadow-slate-900/50 transition-all duration-300 group backdrop-blur-sm relative overflow-hidden">
                  <div className="absolute right-0 top-0 p-6 opacity-5 group-hover:opacity-10 transition-opacity duration-300">
                    <span
                      className={`material-symbols-outlined text-7xl ${
                        stat.color === "primary"
                          ? "text-blue-500"
                          : stat.color === "blue"
                          ? "text-blue-500"
                          : "text-rose-500"
                      }`}>
                      {stat.icon}
                    </span>
                  </div>
                  <p className="text-slate-600 dark:text-slate-400 text-sm font-semibold uppercase tracking-wider mb-2">
                    {stat.label}
                  </p>
                  <div className="flex items-end gap-3">
                    <h3 className="text-4xl font-black text-slate-900 dark:text-white">
                      {stat.value}
                    </h3>
                    <span
                      className={`text-sm font-bold px-3 py-1 rounded-lg flex items-center mb-1 ${
                        stat.color === "primary"
                          ? "text-emerald-600 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-500/15"
                          : stat.color === "blue"
                          ? "text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-500/15"
                          : "text-rose-600 dark:text-rose-400 bg-rose-100 dark:bg-rose-500/15"
                      }`}>
                      {stat.isBadge ? (
                        stat.trend
                      ) : (
                        <>
                          <span className="material-symbols-outlined text-sm mr-1">
                            trending_up
                          </span>
                          {stat.trend}
                        </>
                      )}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Add Target Section */}
            <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm p-8 flex flex-col gap-6 backdrop-blur-sm">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2.5 bg-gradient-to-br from-blue-100 dark:from-blue-500/20 to-cyan-100 dark:to-cyan-500/20 rounded-lg">
                  <span className="material-symbols-outlined text-blue-600 dark:text-blue-400 text-xl">
                    add_circle
                  </span>
                </div>
                <h3 className="text-2xl font-bold text-slate-900 dark:text-white">
                  Add New Target
                </h3>
              </div>
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1 relative group">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 material-symbols-outlined text-lg group-focus-within:text-blue-500 transition-colors">
                    link
                  </span>
                  <input
                    className="w-full h-12 pl-12 pr-4 rounded-xl bg-slate-50 dark:bg-slate-700/30 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 dark:focus:border-blue-400 outline-none transition-all placeholder:text-slate-500 dark:placeholder:text-slate-400 font-medium"
                    placeholder="Enter domain (e.g. example.com) or IP address..."
                    type="text"
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                  />
                </div>
                <button className="h-12 px-7 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold rounded-xl transition-all flex items-center justify-center gap-2 whitespace-nowrap shadow-lg shadow-blue-600/30 hover:shadow-blue-600/40 transform hover:scale-105 active:scale-95">
                  <span>Add Target</span>
                  <span className="material-symbols-outlined text-lg">
                    arrow_forward
                  </span>
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-3 pt-6 border-t border-slate-200 dark:border-slate-700">
                {/* File Upload with Drag & Drop */}
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
                      console.log("File dropped:", files[0].name);
                      alert(`File "${files[0].name}" ready for scanning`);
                    }
                  }}
                  className={`flex-1 min-w-72 flex items-center justify-center gap-3 px-6 py-4 rounded-xl border-2 border-dashed transition-all cursor-pointer ${
                    dragActive
                      ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10"
                      : "border-slate-200 dark:border-slate-700 hover:border-blue-400 dark:hover:border-blue-600 bg-slate-50 dark:bg-slate-800/30 hover:bg-blue-50 dark:hover:bg-blue-500/5"
                  }`}>
                  <span
                    className={`material-symbols-outlined text-2xl transition-colors ${
                      dragActive
                        ? "text-blue-600 dark:text-blue-400"
                        : "text-slate-400"
                    }`}>
                    upload_file
                  </span>
                  <div className="text-left">
                    <p
                      className={`text-sm font-semibold ${
                        dragActive
                          ? "text-blue-600 dark:text-blue-400"
                          : "text-slate-700 dark:text-slate-300"
                      }`}>
                      Drop file here to scan
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Supports: APK, CSV
                    </p>
                  </div>
                </div>
              </div>
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
                                    className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                                      target.riskLevel === "High"
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
