'use client';

import { useState } from 'react';
import Link from 'next/link';
import axiosInstance from '@/services/apiClient';

export default function Home() {
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [openActionMenu, setOpenActionMenu] = useState<number | null>(null);

  const handleHealthCheck = async () => {
    try {
      const response = await axiosInstance.get('/health');
      const data = await response.data;
      alert('API Health: ' + data.status);
    } catch (error) {
      alert('Health check failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  const vulnerabilities = [
    {
      id: 1,
      severity: 'High',
      severityColor: 'red',
      name: 'Cross-Site Scripting (XSS)',
      code: 'CWE-79',
      asset: '/api/v1/auth/login',
      date: 'Oct 24, 2023',
      status: 'Open',
      scanStatus: 'Completed',
      cvssScore: 7.2,
      description: 'The application does not properly sanitize user input in the login form, allowing attackers to inject malicious scripts.',
      evidence: "Input field 'username' reflects unsanitized user input: <script>alert('xss')</script>",
      remediation: 'Implement input validation, output encoding, and Content Security Policy (CSP) headers.',
    },
    {
      id: 2,
      severity: 'Medium',
      severityColor: 'amber',
      name: 'Outdated Library (Lodash)',
      code: 'CVE-2023-1234',
      asset: 'package.json',
      date: 'Oct 22, 2023',
      status: 'Open',
      scanStatus: 'Completed',
      cvssScore: 5.3,
      description: 'The application uses an outdated version of Lodash library with known vulnerabilities.',
      evidence: 'Lodash version 4.17.15 detected in node_modules. Current version: 4.17.21',
      remediation: 'Update Lodash to version 4.17.21 or later: npm install lodash@latest',
    },
    {
      id: 3,
      severity: 'Low',
      severityColor: 'blue',
      name: 'Missing Alt Text',
      code: 'Accessibility',
      asset: '/landing-page',
      date: 'Oct 20, 2023',
      status: 'Fixed',
      scanStatus: 'Completed',
      cvssScore: 2.1,
      description: 'Images on the landing page are missing alternative text attributes required for accessibility.',
      evidence: '<img src="hero.png" /> - No alt attribute found',
      remediation: 'Add descriptive alt text to all images: <img src="hero.png" alt="Hero banner" />',
    },
    {
      id: 4,
      severity: 'High',
      severityColor: 'red',
      name: 'SQL Injection',
      code: 'CWE-89',
      asset: '/api/v1/users/query',
      date: 'Oct 19, 2023',
      status: 'Open',
      scanStatus: 'In Progress',
      cvssScore: 8.6,
      description: 'The query endpoint concatenates user input directly into SQL queries without parameterization.',
      evidence: "Payload: ' OR '1'='1 returns all records from users table",
      remediation: 'Use parameterized queries with prepared statements to prevent SQL injection attacks.',
    },
    {
      id: 5,
      severity: 'Medium',
      severityColor: 'amber',
      name: 'Insecure Direct Object Ref',
      code: 'IDOR',
      asset: '/profile/view',
      date: 'Oct 15, 2023',
      status: 'Accepted',
      scanStatus: 'Completed',
      cvssScore: 5.4,
      description: 'The application fails to properly validate user access controls, allowing users to view other users\' profiles by manipulating the user ID parameter.',
      evidence: 'Accessing /profile/view?id=2 while logged in as user 1 displays user 2\'s sensitive information.',
      remediation: 'Implement proper authorization checks to verify the user owns or has permission to access the requested resource before returning data.',
    },
  ];

  const stats = [
    { label: 'Total Risks', value: '124', trend: '+2%', trendUp: true, icon: 'shield', bgColor: 'bg-gradient-to-br from-blue-600 to-blue-400', borderColor: 'border-blue-500/30', iconColor: 'text-black-400' },
    { label: 'Critical Vulns', value: '12', trend: '+5%', trendUp: true, icon: 'warning', bgColor: 'bg-gradient-to-br from-red-600 to-red-400', borderColor: 'border-red-500/30', iconColor: 'text-black-400' },
    { label: 'Open Issues', value: '45', trend: '-10%', trendUp: false, icon: 'bug_report', bgColor: 'bg-gradient-to-br from-orange-600 to-orange-400', borderColor: 'border-orange-500/30', iconColor: 'text-black-500' },
    { label: 'Remediation Rate', value: '85%', trend: '+12%', trendUp: true, icon: 'check_circle', bgColor: 'bg-gradient-to-br from-emerald-600 to-emerald-400', borderColor: 'border-emerald-500/30', iconColor: 'text-black-400' },
  ];

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard', active: true, href: '/' },
    { label: 'Targets', icon: 'target', active: false, href: '/targets' },
    { label: 'Scans', icon: 'radar', active: false, href: '/scans' },
    { label: 'Reports', icon: 'description', active: false, href: '/reports' },
    { label: 'Settings', icon: 'settings', active: false, href: '/settings' },
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
                <span className="material-symbols-outlined text-xl font-bold">shield_lock</span>
              </div>
              <div className="flex flex-col">
                <h1 className="text-slate-900 dark:text-white text-base font-bold leading-tight">NapScan Pro</h1>
                <p className="text-slate-500 dark:text-slate-400 text-xs">Security</p>
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
                      ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/20'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
                >
                  <span className={`material-symbols-outlined text-xl transition-transform ${item.active ? 'fill-current scale-110' : 'group-hover:scale-110'}`}>
                    {item.icon}
                  </span>
                  <span className={`text-sm font-semibold tracking-wide ${item.active ? 'text-white' : 'text-slate-700 dark:text-slate-300'}`}>{item.label}</span>
                </Link>
              ))}
              <button onClick={handleHealthCheck} className="mt-4 w-full bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-300 hover:bg-green-200 dark:hover:bg-green-500/30 font-semibold text-sm px-4 py-3 rounded-xl transition-colors flex items-center justify-center gap-2">
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
              <p className="text-slate-900 dark:text-white text-sm font-semibold truncate">Alex Morgan</p>
              <p className="text-slate-500 dark:text-slate-500 text-xs truncate">Security Analyst</p>
            </div>
            <span className="material-symbols-outlined text-slate-600 dark:text-slate-400 text-lg">expand_more</span>
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
            <span className="material-symbols-outlined text-slate-400 text-[20px]">search</span>
            <input
              className="bg-transparent border-none text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-400 focus:ring-0 w-full ml-3 h-6 font-medium"
              placeholder="Search security issues..."
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-5 ml-auto">
            <button className="relative p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
              <span className="material-symbols-outlined text-xl">notifications</span>
              <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border-2 border-white dark:border-slate-950 shadow-md"></span>
            </button>
            <button className="p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
              <span className="material-symbols-outlined text-xl">help</span>
            </button>
            <div className="h-6 w-px bg-slate-200 dark:bg-slate-700"></div>
            <button className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300 hover:text-blue-600 dark:hover:text-blue-400 transition-colors px-3 py-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800">
              <span>Docs</span>
              <span className="material-symbols-outlined text-lg">open_in_new</span>
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
                Monitor and manage identified vulnerabilities across your infrastructure
              </p>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 p-6 shadow-sm hover:shadow-md transition-all group"
                >
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <p className="text-slate-600 dark:text-slate-400 text-xs font-semibold uppercase tracking-wider">{stat.label}</p>
                      <p className="text-slate-900 dark:text-white text-2xl font-bold mt-1">{stat.value}</p>
                    </div>
                    <div className={`p-3 rounded-xl ${stat.bgColor} group-hover:scale-110 transition-transform`}>
                      <span className={`material-symbols-outlined text-2xl ${stat.iconColor}`}>{stat.icon}</span>
                    </div>
                  </div>
                  <div className={`flex items-center gap-2 text-sm font-semibold ${stat.trendUp ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                    <span className="material-symbols-outlined text-base">{stat.trendUp ? 'trending_up' : 'trending_down'}</span>
                    <span>{stat.trend}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Vulnerabilities Table */}
            <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
              {/* Table Header */}
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-6 border-b border-slate-200 dark:border-slate-700">
                <div className="flex-1">
                  <h3 className="text-slate-900 dark:text-white text-xl font-bold">Identified Vulnerabilities</h3>
                  <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">Manage and remediate security risks across your assets</p>
                </div>
                <div className="flex gap-3 w-full md:w-auto">
                  {/* Search Input */}
                  <div className="relative flex-1 md:flex-none group">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 material-symbols-outlined text-[20px]">search</span>
                    <input
                      className="h-10 w-full md:w-64 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white text-sm rounded-xl pl-10 pr-4 border border-slate-200 dark:border-slate-700 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/50 dark:focus:border-blue-400 placeholder-slate-500 dark:placeholder-slate-400 transition-all"
                      placeholder="Search risks..."
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto max-h-96">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-700/30">
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">ID</th>
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">Asset</th>
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">Vulnerability</th>
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">Severity</th>
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">Scan Status</th>
                      <th className="px-6 py-4 text-left font-semibold text-slate-700 dark:text-slate-300 uppercase text-xs tracking-wider">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {vulnerabilities.map((vuln) => (
                      <>
                        <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="font-semibold text-slate-900 dark:text-white">#{vuln.id}</span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-slate-700 dark:text-slate-300">{vuln.asset}</td>
                          <td className="px-6 py-4 max-w-xs text-slate-700 dark:text-slate-300">
                            <div className="flex items-center gap-2">
                              <span className="truncate">{vuln.name}</span>
                              <button 
                                onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                                className="flex items-center text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-semibold text-sm transition-colors group/btn hover:bg-blue-100 dark:hover:bg-blue-500/10 rounded-lg p-1"
                                title="Show Details"
                              >
                                <span className={`material-symbols-outlined text-base transition-transform duration-300 ${expandedVuln === vuln.id ? 'rotate-180' : ''}`}>expand_more</span>
                              </button>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div
                              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                                vuln.severity === 'Critical'
                                  ? 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-red-300 dark:border-red-500/30'
                                  : vuln.severity === 'High'
                                    ? 'bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-500/30'
                                    : vuln.severity === 'Medium'
                                      ? 'bg-yellow-100 dark:bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 border-yellow-300 dark:border-yellow-500/30'
                                      : 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-500/30'
                              }`}
                            >
                              <span className="material-symbols-outlined text-sm">warning</span>
                              {vuln.severity}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div
                              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                                vuln.scanStatus === 'Completed'
                                  ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-500/30'
                                  : vuln.scanStatus === 'In Progress'
                                    ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-500/30'
                                    : 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-500/30'
                              }`}
                            >
                              <span className="material-symbols-outlined text-sm">
                                {vuln.scanStatus === 'Completed' ? 'check_circle' : vuln.scanStatus === 'In Progress' ? 'schedule' : 'pending'}
                              </span>
                              {vuln.scanStatus}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="relative">
                              <button 
                                onClick={() => setOpenActionMenu(openActionMenu === vuln.id ? null : vuln.id)}
                                className="flex items-center gap-2 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 font-semibold text-sm transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
                              >
                                <span className="material-symbols-outlined text-base">more_vert</span>
                              </button>
                              {openActionMenu === vuln.id && (
                                <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg z-10">
                                  <button
                                    onClick={() => {
                                      alert('Rescan untuk vulnerability ' + vuln.name);
                                      setOpenActionMenu(null);
                                    }}
                                    className="w-full text-left px-4 py-2.5 text-slate-700 dark:text-slate-300 hover:bg-cyan-100 dark:hover:bg-cyan-500/20 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors flex items-center gap-2 border-b border-slate-200 dark:border-slate-700"
                                  >
                                    <span className="material-symbols-outlined text-base">refresh</span>
                                    <span className="font-semibold">Rescan</span>
                                  </button>
                                  <button
                                    onClick={() => {
                                      if (confirm('Yakin mau hapus vulnerability ini?')) {
                                        alert('Vulnerability ' + vuln.name + ' berhasil dihapus');
                                      }
                                      setOpenActionMenu(null);
                                    }}
                                    className="w-full text-left px-4 py-2.5 text-slate-700 dark:text-slate-300 hover:bg-red-100 dark:hover:bg-red-500/20 hover:text-red-700 dark:hover:text-red-300 transition-colors flex items-center gap-2"
                                  >
                                    <span className="material-symbols-outlined text-base">delete</span>
                                    <span className="font-semibold">Delete</span>
                                  </button>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                        {expandedVuln === vuln.id && (
                          <tr className="bg-blue-50 dark:bg-blue-500/5 border-t border-b border-blue-200 dark:border-blue-500/20">
                            <td colSpan={6} className="px-6 py-8">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {/* Left Column */}
                                <div className="flex flex-col gap-6">
                                  {/* CVSS Score */}
                                  <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="material-symbols-outlined text-lg text-blue-600 dark:text-blue-400">info</span>
                                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">CVSS Score</p>
                                    </div>
                                    <div className="flex items-center gap-3">
                                      <div className={`w-16 h-16 rounded-full flex items-center justify-center font-bold text-lg ${
                                        vuln.cvssScore >= 9 ? 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-300 border-2 border-red-300 dark:border-red-500/30' :
                                        vuln.cvssScore >= 7 ? 'bg-orange-100 dark:bg-orange-500/20 text-orange-700 dark:text-orange-300 border-2 border-orange-300 dark:border-orange-500/30' :
                                        vuln.cvssScore >= 4 ? 'bg-yellow-100 dark:bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 border-2 border-yellow-300 dark:border-yellow-500/30' :
                                        'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-2 border-blue-300 dark:border-blue-500/30'
                                      }`}>
                                        {vuln.cvssScore}
                                      </div>
                                      <div className="flex flex-col">
                                        <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase">Severity Rating</p>
                                        <p className="text-sm font-bold text-slate-900 dark:text-white">{
                                          vuln.cvssScore >= 9 ? 'Critical' :
                                          vuln.cvssScore >= 7 ? 'High' :
                                          vuln.cvssScore >= 4 ? 'Medium' :
                                          'Low'
                                        }</p>
                                      </div>
                                    </div>
                                  </div>

                                  {/* Description */}
                                  <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="material-symbols-outlined text-lg text-blue-600 dark:text-blue-400">description</span>
                                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Description</p>
                                    </div>
                                    <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-white dark:bg-slate-800/30 rounded-lg p-4 border border-slate-200 dark:border-slate-700/50">
                                      {vuln.description}
                                    </p>
                                  </div>
                                </div>

                                {/* Right Column */}
                                <div className="flex flex-col gap-6">
                                  {/* Evidence */}
                                  <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="material-symbols-outlined text-lg text-blue-600 dark:text-blue-400">bug_report</span>
                                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Evidence</p>
                                    </div>
                                    <div className="bg-white dark:bg-slate-800/30 rounded-lg p-4 border border-slate-200 dark:border-slate-700/50 font-mono text-xs text-slate-700 dark:text-slate-300 overflow-x-auto break-words whitespace-pre-wrap">
                                      {vuln.evidence}
                                    </div>
                                  </div>

                                  {/* Remediation */}
                                  <div className="flex flex-col gap-2">
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="material-symbols-outlined text-lg text-emerald-600 dark:text-emerald-400">build</span>
                                      <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Remediation Steps</p>
                                    </div>
                                    <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-white dark:bg-slate-800/30 rounded-lg p-4 border border-slate-200 dark:border-slate-700/50">
                                      {vuln.remediation}
                                    </p>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}