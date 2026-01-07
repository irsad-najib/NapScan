'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function ReportGenerationPage() {
  const [selectedFramework, setSelectedFramework] = useState('soc2');
  const [reportPeriod, setReportPeriod] = useState('Last 30 Days');
  const [includeExecutiveSummary, setIncludeExecutiveSummary] = useState(true);
  const [showRemediationSteps, setShowRemediationSteps] = useState(true);
  const [exportFormat, setExportFormat] = useState('pdf');

  const frameworks = [
    {
      id: 'soc2',
      name: 'SOC 2 Type II',
      subtitle: 'Trust Services Criteria',
      icon: 'verified',
    },
    {
      id: 'iso27001',
      name: 'ISO 27001',
      subtitle: 'Information Security',
      icon: 'globe',
    },
    {
      id: 'hipaa',
      name: 'HIPAA',
      subtitle: 'Health Insurance',
      icon: 'local_hospital',
    },
    {
      id: 'gdpr',
      name: 'GDPR',
      subtitle: 'Data Protection',
      icon: 'lock',
    },
  ];

  const recentReports = [
    {
      id: 1,
      name: 'Q3_Compliance_Audit.pdf',
      date: 'Oct 15, 2023',
      framework: 'SOC 2',
      status: 'Ready',
      statusColor: 'green',
    },
    {
      id: 2,
      name: 'Weekly_Vuln_Scan_09.pdf',
      date: 'Oct 08, 2023',
      framework: 'Internal',
      status: 'Ready',
      statusColor: 'green',
    },
  ];

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard', href: '/' },
    { label: 'Targets', icon: 'target', href: '/targets' },
    { label: 'Scans', icon: 'radar', href: '/scans' },
    { label: 'Reports', icon: 'description', href: '/reports', active: true },
    { label: 'Settings', icon: 'settings', href: '/settings' },
  ];

  return (
    <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
      {/* Top Nav */}
      <header className="fixed top-0 left-0 right-0 flex items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 backdrop-blur-sm px-8 py-4 z-20 h-16">
        <div className="flex items-center gap-4 text-slate-900 dark:text-white">
          <div className="size-10 flex items-center justify-center bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg text-white shadow-lg shadow-blue-500/20">
            <span className="material-symbols-outlined text-xl">shield_lock</span>
          </div>
          <h2 className="text-xl font-bold leading-tight">SecScan Pro</h2>
        </div>
        <div className="flex flex-1 justify-end gap-6 items-center">
          <label className="flex flex-col min-w-44 !h-10 max-w-64 hidden md:flex">
            <div className="flex w-full flex-1 items-stretch rounded-xl h-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 focus-within:ring-2 focus-within:ring-blue-500/50 transition-all">
              <div className="text-slate-400 dark:text-slate-500 flex border-none items-center justify-center pl-4 rounded-l-xl">
                <span className="material-symbols-outlined text-[20px]">search</span>
              </div>
              <input
                className="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-xl focus:outline-0 focus:ring-0 border-none bg-transparent h-full placeholder:text-slate-500 dark:placeholder:text-slate-400 px-4 rounded-l-none border-l-0 pl-2 text-base font-medium leading-normal text-slate-900 dark:text-white"
                placeholder="Search reports..."
              />
            </div>
          </label>
          <button className="bg-transparent border-none text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800">
            <span className="material-symbols-outlined text-xl">notifications</span>
          </button>
          <div
            className="bg-center bg-no-repeat aspect-square bg-cover rounded-lg size-10 ring-2 ring-blue-500/20"
            style={{
              backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuAGj2NrFc2bVisNxFCBOaibhwkmt-rCATaaj2U7YsdTAHO8C9tkwRJUlkpL1wE-JpxNXy3YsNuaaWfw7patlk2aJD6H8NYOMh7cwdXG_kzmhIa3kF0VelIdKjw-fROzZM3aCS6Crs73QhXwBdHNDx8tfxUT_KArN5ulgZ85pZmzbbXwwbfS9yFnOkUS8VPiGYkpz7fcS8aj0YOYHIlhvuGZHVE0LcI5KFY791FOcTUwWRMbzirI7pvl5kDvKhDsqe9x1ItbquUtm5Gw")`,
            }}
          />
        </div>
      </header>

      <div className="flex h-full overflow-hidden pt-16">
        {/* Sidebar */}
        <aside className="hidden lg:flex w-64 flex-col border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 gap-6 overflow-y-auto">
          <nav className="flex flex-col gap-2">
            {navItems.map((item) => (
              <Link
                key={item.label}
                href={item.href}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
                  item.active
                    ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/20'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                <span className={`material-symbols-outlined text-xl transition-transform ${item.active ? 'fill-current scale-110' : 'group-hover:scale-110'}`}>{item.icon}</span>
                <p className="text-sm font-semibold leading-normal">{item.label}</p>
              </Link>
            ))}
          </nav>
          <div className="mt-auto">
            <div className="p-5 rounded-2xl bg-gradient-to-br from-blue-600/10 to-cyan-600/10 dark:from-blue-500/20 dark:to-cyan-500/20 border border-blue-200 dark:border-blue-500/30">
              <div className="flex items-center gap-2 mb-3">
                <div className="p-2 bg-blue-100 dark:bg-blue-500/20 rounded-lg">
                  <span className="material-symbols-outlined text-blue-600 dark:text-blue-400">verified_user</span>
                </div>
                <span className="text-sm font-bold text-slate-900 dark:text-white">Pro Plan</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mb-4 font-medium">Your license expires in 14 days.</p>
              <button className="w-full py-2 rounded-lg bg-gradient-to-r from-blue-600 to-blue-500 text-white text-xs font-bold hover:shadow-lg hover:shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95">
                Renew Now
              </button>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 px-8 md:px-12 py-10 md:py-12">
          <div className="mx-auto max-w-7xl flex flex-col gap-10">
            {/* Breadcrumbs & Heading */}
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
                <a className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium" href="/">
                  Home
                </a>
                <span className="material-symbols-outlined text-[18px]">chevron_right</span>
                <span className="font-semibold text-slate-900 dark:text-white">Reports</span>
              </div>
              <div>
                <h1 className="text-4xl md:text-5xl font-black leading-tight tracking-tight text-slate-900 dark:text-white mb-2">
                  Report Generation
                </h1>
                <p className="text-slate-600 dark:text-slate-400 text-lg font-medium">
                  Create detailed compliance documents and security summaries for your stakeholders.
                </p>
              </div>
            </div>

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
              {/* Left Column: Configuration */}
              <div className="xl:col-span-8 flex flex-col gap-8">
                {/* Step 1: Framework Selection */}
                <section className="bg-white dark:bg-slate-800/50 rounded-2xl p-8 border border-slate-200 dark:border-slate-700 shadow-sm backdrop-blur-sm">
                  <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
                    <span className="flex items-center justify-center size-7 rounded-full bg-gradient-to-br from-blue-600 to-blue-500 text-white text-sm font-bold">
                      1
                    </span>
                    Select Framework
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {frameworks.map((framework) => (
                      <label
                        key={framework.id}
                        className={`cursor-pointer group relative flex flex-col items-start gap-3 p-5 rounded-2xl border-2 transition-all ${
                          selectedFramework === framework.id
                            ? 'border-blue-500 bg-blue-50 dark:bg-blue-500/10 shadow-lg shadow-blue-500/20'
                            : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 hover:border-blue-300 dark:hover:border-blue-500/50 hover:shadow-md'
                        }`}
                      >
                        <input
                          checked={selectedFramework === framework.id}
                          onChange={() => setSelectedFramework(framework.id)}
                          className="absolute top-4 right-4 text-blue-600 focus:ring-blue-500 size-5 accent-blue-600 cursor-pointer"
                          name="framework"
                          type="radio"
                        />
                        <div className={`p-3 rounded-xl ${selectedFramework === framework.id ? 'bg-blue-100 dark:bg-blue-500/20' : 'bg-slate-100 dark:bg-slate-700'}`}>
                          <span className={`material-symbols-outlined text-2xl ${selectedFramework === framework.id ? 'text-blue-600 dark:text-blue-400' : 'text-slate-600 dark:text-slate-400'}`}>
                            {framework.icon}
                          </span>
                        </div>
                        <div>
                          <p className="font-bold text-slate-900 dark:text-white">{framework.name}</p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-medium">{framework.subtitle}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </section>

                {/* Step 2: Scope & Filters */}
                <section className="bg-white dark:bg-slate-800/50 rounded-2xl p-8 border border-slate-200 dark:border-slate-700 shadow-sm backdrop-blur-sm">
                  <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
                    <span className="flex items-center justify-center size-7 rounded-full bg-gradient-to-br from-blue-600 to-blue-500 text-white text-sm font-bold">
                      2
                    </span>
                    Scope & Filters
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Date Range */}
                    <div className="flex flex-col gap-2">
                      <label className="text-sm font-bold text-slate-900 dark:text-white">Reporting Period</label>
                      <div className="relative">
                        <select
                          value={reportPeriod}
                          onChange={(e) => setReportPeriod(e.target.value)}
                          className="w-full h-11 bg-slate-100 dark:bg-slate-700/50 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white text-sm rounded-xl focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 p-2.5 font-medium cursor-pointer appearance-none transition-all hover:border-slate-400 dark:hover:border-slate-500"
                        >
                          <option>Last 30 Days</option>
                          <option>Last Quarter (Q3 2023)</option>
                          <option>Year to Date</option>
                          <option>Custom Range</option>
                        </select>
                      </div>
                    </div>

                    {/* Assets */}
                    <div className="flex flex-col gap-2">
                      <label className="text-sm font-bold text-slate-900 dark:text-white">Included Assets</label>
                      <div className="relative">
                        <button className="flex items-center justify-between w-full h-11 px-3 py-2 bg-slate-100 dark:bg-slate-700/50 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white text-sm rounded-xl hover:border-blue-400 dark:hover:border-blue-500 transition-all font-medium">
                          <span>All Production Assets (142)</span>
                          <span className="material-symbols-outlined text-sm">expand_more</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-6 border-t border-slate-200 dark:border-slate-700">
                    <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-4">Report Customization</h4>
                    <div className="flex flex-col gap-4">
                      <label className="flex items-center gap-3 cursor-pointer group">
                        <div className="relative inline-flex items-center">
                          <input
                            checked={includeExecutiveSummary}
                            onChange={(e) => setIncludeExecutiveSummary(e.target.checked)}
                            className="sr-only peer"
                            type="checkbox"
                          />
                          <div className="w-11 h-6 bg-slate-300 dark:bg-slate-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300/50 dark:peer-focus:ring-blue-800/50 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-gradient-to-r peer-checked:from-blue-600 peer-checked:to-blue-500"></div>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">Include Executive Summary</span>
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer group">
                        <div className="relative inline-flex items-center">
                          <input
                            checked={showRemediationSteps}
                            onChange={(e) => setShowRemediationSteps(e.target.checked)}
                            className="sr-only peer"
                            type="checkbox"
                          />
                          <div className="w-11 h-6 bg-slate-300 dark:bg-slate-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300/50 dark:peer-focus:ring-blue-800/50 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-gradient-to-r peer-checked:from-blue-600 peer-checked:to-blue-500"></div>
                        </div>
                        <span className="text-sm font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">Show detailed remediation steps</span>
                      </label>
                    </div>
                  </div>
                </section>

                {/* Recent Reports Table */}
                <section className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
                  <div className="px-8 py-5 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center bg-slate-100/50 dark:bg-slate-700/20">
                    <h3 className="text-xl font-bold text-slate-900 dark:text-white">Recent Reports</h3>
                    <a className="text-sm text-blue-600 dark:text-blue-400 font-semibold hover:text-blue-700 dark:hover:text-blue-300 transition-colors" href="#">
                      View All
                    </a>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left text-slate-700 dark:text-slate-300">
                      <thead className="text-xs uppercase bg-slate-100 dark:bg-slate-700/30 text-slate-900 dark:text-slate-200 font-bold">
                        <tr>
                          <th className="px-6 py-4">Report Name</th>
                          <th className="px-6 py-4">Date</th>
                          <th className="px-6 py-4">Framework</th>
                          <th className="px-6 py-4">Status</th>
                          <th className="px-6 py-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                        {recentReports.map((report) => (
                          <tr
                            key={report.id}
                            className="bg-white dark:bg-slate-800/30 hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors"
                          >
                            <td className="px-6 py-4 font-semibold text-slate-900 dark:text-white">{report.name}</td>
                            <td className="px-6 py-4 text-slate-600 dark:text-slate-400">{report.date}</td>
                            <td className="px-6 py-4">
                              <span className="px-3 py-1.5 rounded-lg bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 text-xs font-bold">
                                {report.framework}
                              </span>
                            </td>
                            <td className={`px-6 py-4 font-bold ${report.statusColor === 'green' ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                              {report.status}
                            </td>
                            <td className="px-6 py-4 text-right">
                              <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:bg-blue-100/50 dark:hover:bg-blue-500/20 p-2 rounded-lg transition-all transform hover:scale-110">
                                <span className="material-symbols-outlined text-lg">download</span>
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              </div>

              {/* Right Column: Preview & Action */}
              <div className="xl:col-span-4 flex flex-col gap-6">
                <div className="sticky top-6 bg-surface-light dark:bg-[#1e293b] rounded-xl p-6 border border-[#e5e7eb] dark:border-[#232f48] shadow-lg flex flex-col gap-6">
                  <h3 className="text-lg font-bold text-[#111418] dark:text-white border-b border-[#e5e7eb] dark:border-[#232f48] pb-4">
                    Report Preview
                  </h3>

                  {/* Visual Summary */}
                  <div className="flex items-center gap-4">
                    <div className="relative size-24 shrink-0">
                      <svg className="size-full rotate-[-90deg]" viewBox="0 0 36 36">
                        {/* Background Circle */}
                        <path
                          className="text-gray-200 dark:text-gray-700"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="4"
                        ></path>
                        {/* Progress Circle */}
                        <path
                          className="text-primary"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                          fill="none"
                          stroke="currentColor"
                          strokeDasharray="75, 100"
                          strokeWidth="4"
                        ></path>
                      </svg>
                      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
                        <span className="text-2xl font-bold text-[#111418] dark:text-white">85%</span>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1 w-full">
                      <div className="flex justify-between text-sm">
                        <span className="text-[#637588] dark:text-[#92a4c9]">Passing</span>
                        <span className="font-bold text-green-500">243</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-[#637588] dark:text-[#92a4c9]">Failed</span>
                        <span className="font-bold text-red-500">12</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-[#637588] dark:text-[#92a4c9]">Risks</span>
                        <span className="font-bold text-yellow-500">45</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-[#f0f2f5] dark:bg-[#111722] rounded-lg text-sm text-[#637588] dark:text-[#92a4c9]">
                    <div className="flex justify-between mb-2">
                      <span>Est. Pages:</span>
                      <span className="font-medium text-[#111418] dark:text-white">~45 Pages</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Est. Time:</span>
                      <span className="font-medium text-[#111418] dark:text-white">2-3 mins</span>
                    </div>
                  </div>

                  <div className="flex flex-col gap-3">
                    <p className="text-sm font-medium text-[#111418] dark:text-white">Export Format</p>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setExportFormat('pdf')}
                        className={`flex-1 py-2 px-3 rounded-lg border transition-colors text-sm font-medium flex items-center justify-center gap-2 ${
                          exportFormat === 'pdf'
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'border-[#e5e7eb] dark:border-[#232f48] bg-transparent text-[#637588] dark:text-[#92a4c9] hover:bg-gray-100 dark:hover:bg-[#232f48]'
                        }`}
                      >
                        <span className="material-symbols-outlined text-lg">picture_as_pdf</span>
                        PDF
                      </button>
                      <button
                        onClick={() => setExportFormat('csv')}
                        className={`flex-1 py-2 px-3 rounded-lg border transition-colors text-sm font-medium flex items-center justify-center gap-2 ${
                          exportFormat === 'csv'
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'border-[#e5e7eb] dark:border-[#232f48] bg-transparent text-[#637588] dark:text-[#92a4c9] hover:bg-gray-100 dark:hover:bg-[#232f48]'
                        }`}
                      >
                        <span className="material-symbols-outlined text-lg">table_chart</span>
                        CSV
                      </button>
                      <button
                        onClick={() => setExportFormat('json')}
                        className={`flex-1 py-2 px-3 rounded-lg border transition-colors text-sm font-medium flex items-center justify-center gap-2 ${
                          exportFormat === 'json'
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'border-[#e5e7eb] dark:border-[#232f48] bg-transparent text-[#637588] dark:text-[#92a4c9] hover:bg-gray-100 dark:hover:bg-[#232f48]'
                        }`}
                      >
                        <span className="material-symbols-outlined text-lg">data_object</span>
                        JSON
                      </button>
                    </div>
                  </div>

                  <button className="w-full bg-primary hover:bg-blue-600 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-all flex items-center justify-center gap-2 mt-2">
                    <span className="material-symbols-outlined">auto_fix_high</span>
                    Generate Report
                  </button>

                  <p className="text-xs text-center text-[#637588] dark:text-[#92a4c9]">
                    Report will be emailed to <span className="text-[#111418] dark:text-white font-medium">admin@security.inc</span>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
