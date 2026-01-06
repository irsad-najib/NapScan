'use client';

import { useState } from 'react';

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
    { label: 'Dashboard', icon: 'dashboard' },
    { label: 'Scans', icon: 'radar' },
    { label: 'Assets', icon: 'dns' },
    { label: 'Reports', icon: 'description', active: true },
    { label: 'Settings', icon: 'settings' },
  ];

  return (
    <div className="relative flex h-screen w-full flex-col overflow-hidden bg-background-light dark:bg-background-dark">
      {/* Top Nav */}
      <header className="flex items-center justify-between whitespace-nowrap border-b border-solid border-[#e5e7eb] dark:border-[#232f48] bg-surface-light dark:bg-[#111722] px-6 py-3 z-20">
        <div className="flex items-center gap-4 text-[#111418] dark:text-white">
          <div className="size-8 flex items-center justify-center text-primary">
            <span className="material-symbols-outlined text-3xl">security</span>
          </div>
          <h2 className="text-lg font-bold leading-tight tracking-[-0.015em]">SecurityScanner</h2>
        </div>
        <div className="flex flex-1 justify-end gap-6 items-center">
          <label className="flex flex-col min-w-40 !h-10 max-w-64 hidden md:flex">
            <div className="flex w-full flex-1 items-stretch rounded-lg h-full bg-[#f0f2f5] dark:bg-[#232f48]">
              <div className="text-[#637588] dark:text-[#92a4c9] flex border-none items-center justify-center pl-4 rounded-l-lg">
                <span className="material-symbols-outlined text-[20px]">search</span>
              </div>
              <input
                className="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-lg focus:outline-0 focus:ring-0 border-none bg-transparent h-full placeholder:text-[#637588] dark:placeholder:text-[#92a4c9] px-4 rounded-l-none border-l-0 pl-2 text-base font-normal leading-normal text-[#111418] dark:text-white"
                placeholder="Search assets..."
              />
            </div>
          </label>
          <button className="bg-transparent border-none text-[#637588] dark:text-[#92a4c9] hover:text-primary transition-colors">
            <span className="material-symbols-outlined">notifications</span>
          </button>
          <div
            className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-10 border-2 border-primary/20"
            style={{
              backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuAGj2NrFc2bVisNxFCBOaibhwkmt-rCATaaj2U7YsdTAHO8C9tkwRJUlkpL1wE-JpxNXy3YsNuaaWfw7patlk2aJD6H8NYOMh7cwdXG_kzmhIa3kF0VelIdKjw-fROzZM3aCS6Crs73QhXwBdHNDx8tfxUT_KArN5ulgZ85pZmzbbXwwbfS9yFnOkUS8VPiGYkpz7fcS8aj0YOYHIlhvuGZHVE0LcI5KFY791FOcTUwWRMbzirI7pvl5kDvKhDsqe9x1ItbquUtm5Gw")`,
            }}
          />
        </div>
      </header>

      <div className="flex h-full overflow-hidden">
        {/* Sidebar */}
        <aside className="hidden lg:flex w-64 flex-col border-r border-[#e5e7eb] dark:border-[#232f48] bg-surface-light dark:bg-[#111722] p-4 gap-4">
          <div className="flex flex-col gap-2">
            {navItems.map((item) => (
              <div
                key={item.label}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition-colors ${
                  item.active
                    ? 'bg-primary/10 text-primary dark:bg-[#232f48] dark:text-white'
                    : 'text-[#637588] dark:text-[#92a4c9] hover:bg-gray-100 dark:hover:bg-[#232f48]'
                }`}
              >
                <span className={`material-symbols-outlined ${item.active ? 'fill-1' : ''}`}>{item.icon}</span>
                <p className="text-sm font-medium leading-normal">{item.label}</p>
              </div>
            ))}
          </div>
          <div className="mt-auto">
            <div className="p-4 rounded-xl bg-gradient-to-br from-primary/20 to-transparent border border-primary/10">
              <div className="flex items-center gap-2 mb-2">
                <span className="material-symbols-outlined text-primary">verified_user</span>
                <span className="text-sm font-bold text-[#111418] dark:text-white">Pro Plan</span>
              </div>
              <p className="text-xs text-[#637588] dark:text-[#92a4c9] mb-3">Your license expires in 14 days.</p>
              <button className="w-full py-1.5 rounded-lg bg-primary text-white text-xs font-medium hover:bg-blue-700 transition-colors">
                Renew Now
              </button>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto bg-background-light dark:bg-background-dark p-6 lg:p-10">
          <div className="mx-auto max-w-6xl flex flex-col gap-8">
            {/* Breadcrumbs & Heading */}
            <div className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-sm text-[#637588] dark:text-[#92a4c9]">
                <a className="hover:text-primary" href="#">
                  Home
                </a>
                <span className="material-symbols-outlined text-[16px]">chevron_right</span>
                <span className="font-medium text-[#111418] dark:text-white">Reports</span>
              </div>
              <div>
                <h1 className="text-3xl lg:text-4xl font-black leading-tight tracking-[-0.033em] text-[#111418] dark:text-white mb-2">
                  Report Generation
                </h1>
                <p className="text-[#637588] dark:text-[#92a4c9] text-base lg:text-lg">
                  Create detailed compliance documents and security summaries for your stakeholders.
                </p>
              </div>
            </div>

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
              {/* Left Column: Configuration */}
              <div className="xl:col-span-8 flex flex-col gap-8">
                {/* Step 1: Framework Selection */}
                <section className="bg-surface-light dark:bg-[#1e293b] rounded-xl p-6 border border-[#e5e7eb] dark:border-[#232f48] shadow-sm">
                  <h3 className="text-lg font-bold text-[#111418] dark:text-white mb-4 flex items-center gap-2">
                    <span className="flex items-center justify-center size-6 rounded-full bg-primary/20 text-primary text-xs font-bold">
                      1
                    </span>
                    Select Framework
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {frameworks.map((framework) => (
                      <label
                        key={framework.id}
                        className={`cursor-pointer group relative flex flex-col items-start gap-3 p-4 rounded-xl border-2 transition-all ${
                          selectedFramework === framework.id
                            ? 'border-primary bg-primary/5 dark:bg-primary/10'
                            : 'border-[#e5e7eb] dark:border-[#232f48] bg-white dark:bg-[#111722] hover:border-primary/50 dark:hover:border-primary/50'
                        }`}
                      >
                        <input
                          checked={selectedFramework === framework.id}
                          onChange={() => setSelectedFramework(framework.id)}
                          className="absolute top-4 right-4 text-primary focus:ring-primary size-5"
                          name="framework"
                          type="radio"
                        />
                        <div className="p-2 rounded-lg bg-white dark:bg-[#111722] shadow-sm">
                          <span className={`material-symbols-outlined text-2xl ${selectedFramework === framework.id ? 'text-primary' : 'text-[#637588] dark:text-[#92a4c9]'}`}>
                            {framework.icon}
                          </span>
                        </div>
                        <div>
                          <p className="font-bold text-[#111418] dark:text-white">{framework.name}</p>
                          <p className="text-xs text-[#637588] dark:text-[#92a4c9] mt-1">{framework.subtitle}</p>
                        </div>
                      </label>
                    ))}
                  </div>
                </section>

                {/* Step 2: Scope & Filters */}
                <section className="bg-surface-light dark:bg-[#1e293b] rounded-xl p-6 border border-[#e5e7eb] dark:border-[#232f48] shadow-sm">
                  <h3 className="text-lg font-bold text-[#111418] dark:text-white mb-6 flex items-center gap-2">
                    <span className="flex items-center justify-center size-6 rounded-full bg-primary/20 text-primary text-xs font-bold">
                      2
                    </span>
                    Scope & Filters
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Date Range */}
                    <div className="flex flex-col gap-2">
                      <label className="text-sm font-medium text-[#111418] dark:text-white">Reporting Period</label>
                      <div className="relative">
                        <select
                          value={reportPeriod}
                          onChange={(e) => setReportPeriod(e.target.value)}
                          className="w-full h-11 bg-[#f0f2f5] dark:bg-[#111722] border border-[#e5e7eb] dark:border-[#232f48] text-[#111418] dark:text-white text-sm rounded-lg focus:ring-primary focus:border-primary p-2.5"
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
                      <label className="text-sm font-medium text-[#111418] dark:text-white">Included Assets</label>
                      <div className="relative">
                        <button className="flex items-center justify-between w-full h-11 px-3 py-2 bg-[#f0f2f5] dark:bg-[#111722] border border-[#e5e7eb] dark:border-[#232f48] text-[#111418] dark:text-white text-sm rounded-lg hover:border-primary/50">
                          <span>All Production Assets (142)</span>
                          <span className="material-symbols-outlined text-sm">expand_more</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-6 border-t border-[#e5e7eb] dark:border-[#232f48]">
                    <h4 className="text-sm font-bold text-[#111418] dark:text-white mb-3">Report Customization</h4>
                    <div className="flex flex-col gap-3">
                      <label className="flex items-center gap-3 cursor-pointer">
                        <div className="relative inline-flex items-center">
                          <input
                            checked={includeExecutiveSummary}
                            onChange={(e) => setIncludeExecutiveSummary(e.target.checked)}
                            className="sr-only peer"
                            type="checkbox"
                          />
                          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary"></div>
                        </div>
                        <span className="text-sm font-medium text-[#111418] dark:text-white">Include Executive Summary</span>
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer">
                        <div className="relative inline-flex items-center">
                          <input
                            checked={showRemediationSteps}
                            onChange={(e) => setShowRemediationSteps(e.target.checked)}
                            className="sr-only peer"
                            type="checkbox"
                          />
                          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary"></div>
                        </div>
                        <span className="text-sm font-medium text-[#111418] dark:text-white">Show detailed remediation steps</span>
                      </label>
                    </div>
                  </div>
                </section>

                {/* Recent Reports Table */}
                <section className="bg-surface-light dark:bg-[#1e293b] rounded-xl border border-[#e5e7eb] dark:border-[#232f48] shadow-sm overflow-hidden">
                  <div className="px-6 py-4 border-b border-[#e5e7eb] dark:border-[#232f48] flex justify-between items-center">
                    <h3 className="text-lg font-bold text-[#111418] dark:text-white">Recent Reports</h3>
                    <a className="text-sm text-primary font-medium hover:underline" href="#">
                      View All
                    </a>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left text-[#637588] dark:text-[#92a4c9]">
                      <thead className="text-xs uppercase bg-[#f0f2f5] dark:bg-[#111722] text-[#111418] dark:text-white">
                        <tr>
                          <th className="px-6 py-3">Report Name</th>
                          <th className="px-6 py-3">Date</th>
                          <th className="px-6 py-3">Framework</th>
                          <th className="px-6 py-3">Status</th>
                          <th className="px-6 py-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentReports.map((report) => (
                          <tr
                            key={report.id}
                            className="bg-white dark:bg-[#1e293b] border-b border-[#e5e7eb] dark:border-[#232f48] hover:bg-gray-50 dark:hover:bg-[#232f48]"
                          >
                            <td className="px-6 py-4 font-medium text-[#111418] dark:text-white">{report.name}</td>
                            <td className="px-6 py-4">{report.date}</td>
                            <td className="px-6 py-4">
                              <span className="px-2 py-1 rounded bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 text-xs">
                                {report.framework}
                              </span>
                            </td>
                            <td className={`px-6 py-4 font-medium ${report.statusColor === 'green' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                              {report.status}
                            </td>
                            <td className="px-6 py-4 text-right">
                              <button className="text-primary hover:text-blue-400">
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
