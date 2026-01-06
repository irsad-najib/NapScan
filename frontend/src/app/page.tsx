'use client';

import { useState } from 'react';

export default function Home() {
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');

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
    },
  ];

  const stats = [
    { label: 'Total Risks', value: '124', trend: '+2%', trendUp: true, icon: 'shield', bgColor: 'bg-gradient-to-br from-blue-600 to-blue-400', borderColor: 'border-blue-500/30', iconColor: 'text-black-400' },
    { label: 'Critical Vulns', value: '12', trend: '+5%', trendUp: true, icon: 'warning', bgColor: 'bg-gradient-to-br from-red-600 to-red-400', borderColor: 'border-red-500/30', iconColor: 'text-black-400' },
    { label: 'Open Issues', value: '45', trend: '-10%', trendUp: false, icon: 'bug_report', bgColor: 'bg-gradient-to-br from-orange-600 to-orange-400', borderColor: 'border-orange-500/30', iconColor: 'text-black-500' },
    { label: 'Remediation Rate', value: '85%', trend: '+12%', trendUp: true, icon: 'check_circle', bgColor: 'bg-gradient-to-br from-emerald-600 to-emerald-400', borderColor: 'border-emerald-500/30', iconColor: 'text-black-400' },
  ];

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard', active: true },
    { label: 'Scans', icon: 'radar', active: false },
    { label: 'Reports', icon: 'description', active: false },
    { label: 'Settings', icon: 'settings', active: false },
  ];

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background-dark dark:bg-background-dark">
      {/* Side Navigation */}
      <aside className="hidden md:flex flex-col w-64 bg-surface-darker border-r border-[#232f48] h-full flex-shrink-0">
        <div className="flex flex-col h-full p-4 justify-between">
          <div className="flex flex-col gap-6">
            {/* User/App Info */}
            <div className="flex gap-3 items-center px-2">
              <div
                className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-10 shadow-lg border border-[#232f48]"
                style={{
                  backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuCh8uYRP-HT-F-XERcS5Eey8codaekqO8OB2xh0uUpbbudDU-w4poJggQ538EII8_qWXNp9iiyhXdDmfvAFNQ_Ltqpn0_ri0HezeEd7kMC8x_Fh_-u_SZv0CWyIVLh5PKGuQbhdq8cFikywQ0HXMRN1VgQ6oyQXarl8BpM2_kF72N_hlRRja1UW2llExWmJLu0bhPiU2qzRO5BxFCB7bx3baPcDNCVQeLdn2NI3ftYREJ9mOBGbZJ-FW_qnKINaOaiRIo2sAQazNTqt")`,
                }}
              />
              <div className="flex flex-col">
                <h1 className="text-white text-base font-bold leading-normal tracking-wide">NapScan</h1>
                <p className="text-[#92a4c9] text-xs font-normal leading-normal">Admin Console</p>
              </div>
            </div>

            {/* Nav Links */}
            <div className="flex flex-col gap-2">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg transition-all group ${
                    item.active
                      ? 'bg-primary text-white shadow-md shadow-blue-900/20'
                      : 'text-[#92a4c9] hover:bg-[#232f48] hover:text-white transition-colors'
                  }`}
                  href="#"
                >
                  <span className="material-symbols-outlined text-white group-hover:scale-110 transition-transform" style={{ fontSize: '24px' }}>
                    {item.icon}
                  </span>
                  <p className="text-sm font-medium leading-normal">{item.label}</p>
                </a>
              ))}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="flex flex-col gap-2 border-t border-[#232f48] pt-4">
            <a className="flex items-center gap-3 px-3 py-2 rounded-lg text-[#92a4c9] hover:bg-[#232f48] hover:text-white transition-colors" href="#">
              <span className="material-symbols-outlined" style={{ fontSize: '24px' }}>
                logout
              </span>
              <p className="text-sm font-medium leading-normal">Sign Out</p>
            </a>
          </div>
        </div>
      </aside>

      {/* Main Content Wrapper */}
      <main className="flex flex-col flex-1 h-full overflow-hidden bg-background-blue dark:bg-background-blue relative">
        {/* Top Navbar */}
        <header className="flex items-center justify-between whitespace-nowrap border-b border-solid border-[#4e586c] bg-surface-darker px-8 py-4 z-10">
          <div className="flex items-center gap-4 text-white">
            <div className="md:hidden text-white cursor-pointer">
              <span className="material-symbols-outlined">menu</span>
            </div>
            <h2 className="text-white text-xl font-bold leading-tight tracking-tight">Security Overview</h2>
          </div>
          <div className="flex gap-3">
            <button className="flex items-center justify-center rounded-lg size-10 hover:bg-[#4e586c] text-[#92a4c9] transition-colors relative">
              <span className="material-symbols-outlined">notifications</span>
              <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border border-[#111722]"></span>
            </button>
            <button className="flex items-center justify-center rounded-lg size-10 hover:bg-[#4e586c] text-[#92a4c9] transition-colors">
              <span className="material-symbols-outlined">account_circle</span>
            </button>
          </div>
        </header>

        {/* Scrollable Content Area */}
        <div className="flex-1 overflow-y-auto p-4 md:p-8">
          <div className="max-w-[1400px] mx-auto flex flex-col gap-6">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {stats.map((stat) => (
                <div key={stat.label} className={`flex flex-col gap-2 rounded-xl p-6 ${stat.bgColor} border-2 ${stat.borderColor} shadow-lg shadow-slate-900/20 relative overflow-hidden group hover:shadow-2xl transition-all`}>
                  <div className="absolute right-0 top-0 p-4 opacity-15 group-hover:opacity-25 transition-opacity">
                    <span className={`material-symbols-outlined ${stat.iconColor}`} style={{ fontSize: '120px' }}>
                      {stat.icon}
                    </span>
                  </div>
                  <p className="text-slate-300 text-xs font-bold uppercase tracking-widest">{stat.label}</p>
                  <div className="flex items-end gap-3 relative z-10">
                    <p className="text-white text-4xl font-black leading-tight">{stat.value}</p>
                    <p className={`text-xs font-bold px-2 py-1 rounded-full flex items-center gap-1 ${stat.trendUp ? 'bg-emerald-500/30 text-emerald-300' : 'bg-red-500/30 text-red-300'}`}>
                      <span className="material-symbols-outlined text-xs">{stat.trendUp ? 'trending_up' : 'trending_down'}</span>
                      {stat.trend}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Main Section */}
            <div className="flex flex-col bg-gray-900 rounded-xl border border-[#232f48] shadow-lg overflow-hidden">
              {/* Toolbar */}
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 p-5 border-b border-[#232f48]">
                <div>
                  <h3 className="text-white text-xl font-bold leading-tight">Identified Vulnerabilities</h3>
                  <p className="text-[#92a4c9] text-sm mt-1">Manage and remediate security risks across your assets.</p>
                </div>
                <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                  {/* Search */}
                  <div className="relative group flex-grow md:flex-grow-0">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-primary transition-colors material-symbols-outlined text-[20px]">
                      search
                    </span>
                    <input
                      className="h-10 w-full md:w-64 bg-[#1e293b] text-white text-sm rounded-lg pl-10 pr-4 border border-[#324467] focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary placeholder-gray-500 transition-all"
                      placeholder="Search risks..."
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                  {/* Filter Button */}
                  <button className="h-10 px-4 flex items-center gap-2 bg-[#1e293b] border border-[#324467] rounded-lg text-white hover:bg-[#2a3855] transition-colors text-sm font-medium">
                    <span className="material-symbols-outlined text-[20px]">filter_list</span>
                    <span className="hidden sm:inline">Filters</span>
                  </button>
                  {/* Export Button */}
                  <button className="h-10 px-4 flex items-center gap-2 bg-primary hover:bg-blue-600 rounded-lg text-white text-sm font-bold transition-colors shadow-lg shadow-blue-900/20">
                    <span className="material-symbols-outlined text-[20px]">download</span>
                    <span className="hidden sm:inline">Export CSV</span>
                  </button>
                </div>
              </div>

              {/* Table Container */}
              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-[#656d7e] border-b border-[#656d7e]">
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b]">Severity</th>
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b]">Vulnerability Name</th>
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b]">Asset / Endpoint</th>
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b]">Date Detected</th>
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b]">Status</th>
                      <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-[#151c2b] text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#232f48]">
                    {vulnerabilities.map((vuln) => (
                      <tr key={vuln.id} className="hover:bg-[#1e293b]/50 transition-colors group cursor-pointer">
                        <td className="py-4 px-6 whitespace-nowrap">
                          {vuln.severity === 'High' && (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-red-500/25 text-red-200 border border-red-500/50 shadow-lg shadow-red-900/20">
                              <span className="size-2 rounded-full bg-red-400 animate-pulse"></span>
                              {vuln.severity}
                            </span>
                          )}
                          {vuln.severity === 'Medium' && (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-amber-500/25 text-amber-200 border border-amber-500/50 shadow-lg shadow-amber-900/20">
                              <span className="size-2 rounded-full bg-amber-400"></span>
                              {vuln.severity}
                            </span>
                          )}
                          {vuln.severity === 'Low' && (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-blue-500/25 text-blue-200 border border-blue-500/50 shadow-lg shadow-blue-900/20">
                              <span className="size-2 rounded-full bg-blue-400"></span>
                              {vuln.severity}
                            </span>
                          )}
                        </td>
                        <td className="py-4 px-6">
                          <div className="flex flex-col">
                            <span className="text-white font-medium text-sm">{vuln.name}</span>
                            <span className="text-xs text-gray-500">{vuln.code}</span>
                          </div>
                        </td>
                        <td className="py-4 px-6 text-[#92a4c9] text-sm font-mono">{vuln.asset}</td>
                        <td className="py-4 px-6 text-[#92a4c9] text-sm">{vuln.date}</td>
                        <td className="py-4 px-6 whitespace-nowrap">
                          {vuln.status === 'Fixed' ? (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-emerald-500/25 text-emerald-200 border border-emerald-500/50 shadow-lg shadow-emerald-900/20">
                              <span className="material-symbols-outlined text-[14px]">check_circle</span>
                              {vuln.status}
                            </span>
                          ) : vuln.status === 'Accepted' ? (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-purple-500/25 text-purple-200 border border-purple-500/50 shadow-lg shadow-purple-900/20">
                              <span className="size-2 rounded-full bg-purple-400"></span>
                              {vuln.status}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold bg-orange-500/25 text-orange-200 border border-orange-500/50 shadow-lg shadow-orange-900/20">
                              <span className="size-2 rounded-full bg-orange-400 animate-pulse"></span>
                              {vuln.status}
                            </span>
                          )}
                        </td>
                        <td className="py-4 px-6 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            {vuln.status === 'Fixed' ? (
                              <button className="text-xs font-bold text-blue-300 hover:text-blue-100 px-3 py-1.5 rounded-lg border border-blue-500/50 bg-blue-500/20 hover:bg-blue-500/30 transition-all shadow-lg shadow-blue-900/20">
                                View Details
                              </button>
                            ) : (
                              <>
                                <button className="text-xs font-bold text-white px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 transition-all shadow-lg shadow-emerald-900/30">
                                  Mark Fixed
                                </button>
                                <button className="text-white p-1.5 rounded-lg bg-slate-700/60 hover:bg-slate-600 transition-all shadow-lg shadow-slate-900/20" title="Accept Risk">
                                  <span className="material-symbols-outlined text-[20px]">verified_user</span>
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex items-center justify-between px-6 py-4 border-t border-[#232f48] bg-[#1e293b]">
                <p className="text-xs text-[#92a4c9]">
                  Showing <span className="text-white font-bold">1-5</span> of <span className="text-white font-bold">124</span> risks
                </p>
                <div className="flex gap-2">
                  <button className="p-1 rounded-md text-[#92a4c9] hover:text-white hover:bg-[#324467] disabled:opacity-50">
                    <span className="material-symbols-outlined">chevron_left</span>
                  </button>
                  <button className="p-1 rounded-md text-[#92a4c9] hover:text-white hover:bg-[#324467]">
                    <span className="material-symbols-outlined">chevron_right</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}