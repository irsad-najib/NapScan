'use client';

import Link from 'next/link';
import { useState } from 'react';
import { scanApi } from '@/services/api';
import axiosInstance from '@/services/apiClient';

export default function ScansPage() {
  const [currentPage, setCurrentPage] = useState(1);
  const [showNewScanForm, setShowNewScanForm] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [selectedScanDetails, setSelectedScanDetails] = useState<any>(null);
  const [selectedTarget, setSelectedTarget] = useState<any>(null);
  const [formData, setFormData] = useState({
    targetId: '',
    scanName: '',
    scanTiming: 'now', // 'now' or 'scheduled'
    scheduledDate: '',
    scheduledTime: '',
    selectedTools: {
      nmap: false,
      zap: false,
      openvas: false,
      nuclei: false,
      sslyze: false,
    },
  });

  const scans = [
    {
      id: 1,
      name: 'Weekly Infrastructure Scan',
      target: 'api.company-prod.com',
      status: 'Completed',
      statusColor: 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/30',
      riskLevel: 'Medium',
      riskColor: 'text-amber-600 dark:text-amber-400',
      vulnerabilities: 23,
      date: 'Oct 20, 2023',
      progress: 100,
    },
    {
      id: 2,
      name: 'Database Security Assessment',
      target: '192.168.10.55',
      status: 'In Progress',
      statusColor: 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/30',
      riskLevel: 'High',
      riskColor: 'text-red-600 dark:text-red-400',
      vulnerabilities: 8,
      date: 'Oct 21, 2023',
      progress: 65,
    },
    {
      id: 3,
      name: 'Web Application Penetration Test',
      target: 'staging.web.app',
      status: 'Pending',
      statusColor: 'bg-slate-100 dark:bg-slate-500/20 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-500/30',
      riskLevel: 'Low',
      riskColor: 'text-emerald-600 dark:text-emerald-400',
      vulnerabilities: 2,
      date: 'Oct 22, 2023',
      progress: 0,
    },
  ];
  const targets = [
    { id: 1, name: 'api.company-prod.com', type: 'Web Application', lastScanned: 'Oct 20, 2023' },
    { id: 2, name: '192.168.10.55', type: 'Network/Server', lastScanned: 'Oct 21, 2023' },
    { id: 3, name: 'staging.web.app', type: 'Web Application', lastScanned: 'Oct 22, 2023' },
    { id: 4, name: 'api.internal.local', type: 'API', lastScanned: 'Oct 23, 2023' },
    { id: 5, name: 'cms.ayolari.net', type: 'Web Application', lastScanned: 'Oct 24, 2023' },
  ];


  const handleStartScan = async () => {
      // if (!formData.targetId) {
      //   alert('Please select a target');
      //   return;
      // }

    const selectedTools = Object.entries(formData.selectedTools)
      .filter(([_, selected]) => selected)
      .map(([tool]) => tool);

    if (selectedTools.length === 0) {
      alert('Please select at least one scanner tool');
      return;
    }

    if (formData.scanTiming === 'scheduled' && (!formData.scheduledDate || !formData.scheduledTime)) {
      alert('Please select date and time for scheduled scan');
      return;
    }

    setIsSubmitting(true);
    try {
      console.log('Starting scan with data:', selectedTarget);

      const selectedTools = Object.entries(formData.selectedTools)
        .filter(([_, selected]) => selected)
        .map(([tool]) => tool);

      for (const tool of selectedTools) {
        const response = await axiosInstance.post(`/api/${tool}/scan`, {
          target:  selectedTarget,
        });
        console.log(`${tool} scan response:`, response);
      }
      
      setShowNewScanForm(false);
      alert('✅ Scan initiated! Job queued for execution.');
    } catch (error) {
      console.error('Error creating scan:', error);
      alert('❌ Failed to create scan. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard', href: '/', active: false },
    { label: 'Targets', icon: 'target', href: '/targets', active: false },
    { label: 'Scans', icon: 'radar', href: '/scans', active: true },
    { label: 'Reports', icon: 'description', href: '/reports', active: false },
    { label: 'Settings', icon: 'settings', href: '/settings', active: false },
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
              placeholder="Search scans..."
              type="text"
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
            {/* Breadcrumbs */}
            <div className="flex items-center gap-2 text-sm">
              <a className="text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium" href="/">
                Home
              </a>
              <span className="material-symbols-outlined text-slate-400 text-[18px]">chevron_right</span>
              <a className="text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors font-medium" href="/scans">
                Scans
              </a>
              {showNewScanForm && (
                <>
                  <span className="material-symbols-outlined text-slate-400 text-[18px]">chevron_right</span>
                  <span className="text-slate-900 dark:text-slate-100 font-semibold">New Scan</span>
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
                  className="flex items-center justify-center gap-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3.5 px-6 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95 shrink-0 h-12 whitespace-nowrap"
                >
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
                    className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 transition-colors"
                  >
                    <span className="material-symbols-outlined">close</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Select Target */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                      Target to Scan <span className="text-red-500">*</span>
                    </label>
                    {/* <select
                      value={formData.targetId}
                      onChange={(e) => {
                      const selectedId = e.target.value;
                      const selected = targets.find(t => t.id.toString() === selectedId);
                      setFormData({ ...formData, targetId: selectedId });
                      setSelectedTarget(selected?.name || null);
                      }}
                      className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    >
                      <option value="">-- Select a target --</option>
                      {targets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} ({target.type})
                      </option>
                      ))}
                    </select> */}
                    <input
                      type="text"
                      list="targets-list"
                      value={selectedTarget || ''}
                      onChange={(e) => {setSelectedTarget(e.target.value);}}
                      placeholder="Type or select a target..."
                      className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    />
                  </div>

                  {/* Scanner Tools Selection */}
                  <div className="md:col-span-2">
                    <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-3">
                      Scanner Tools <span className="text-red-500">*</span>
                    </label>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      {[
                        { id: 'nmap', name: 'Nmap'},
                        { id: 'zap', name: 'OWASP ZAP'},
                        { id: 'openvas', name: 'OpenVAS' },
                        { id: 'nuclei', name: 'Nuclei' },
                        { id: 'sslyze', name: 'SSLyze' },
                      ].map((tool) => (
                        <label
                          key={tool.id}
                          className={`flex items-center gap-3 p-3 rounded-xl border-2 cursor-pointer transition-all ${
                            formData.selectedTools[tool.id as keyof typeof formData.selectedTools]
                              ? 'border-blue-500 bg-blue-50 dark:bg-blue-500/10'
                              : 'border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={formData.selectedTools[tool.id as keyof typeof formData.selectedTools]}
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
                            <span className="material-symbols-outlined text-lg block mb-1">{tool.icon}</span>
                            <span className="text-xs font-semibold text-slate-900 dark:text-white">{tool.name}</span>
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
                          checked={formData.scanTiming === 'now'}
                          onChange={(e) => setFormData({ ...formData, scanTiming: e.target.value })}
                          className="w-4 h-4 cursor-pointer"
                        />
                        <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Start Now</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="radio"
                          name="scanTiming"
                          value="scheduled"
                          checked={formData.scanTiming === 'scheduled'}
                          onChange={(e) => setFormData({ ...formData, scanTiming: e.target.value })}
                          className="w-4 h-4 cursor-pointer"
                        />
                        <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Schedule for Later</span>
                      </label>
                    </div>
                  </div>

                  {/* Scheduled Date & Time */}
                  {formData.scanTiming === 'scheduled' && (
                    <>
                      <div>
                        <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-2">
                          Date <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="date"
                          value={formData.scheduledDate}
                          onChange={(e) => setFormData({ ...formData, scheduledDate: e.target.value })}
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
                          onChange={(e) => setFormData({ ...formData, scheduledTime: e.target.value })}
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
                      onChange={(e) => setFormData({ ...formData, scanName: e.target.value })}
                      placeholder="e.g., Production API Security Check"
                      className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white placeholder-slate-500 dark:placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                    />
                  </div>
                </div>

                {/* Selected Tools Summary */}
                {Object.values(formData.selectedTools).some(v => v) && (
                  <div className="mt-6 p-4 bg-slate-100 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700">
                    <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-2">Selected Scanners</p>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(formData.selectedTools)
                        .filter(([_, selected]) => selected)
                        .map(([tool]) => {
                          const toolNames: Record<string, string> = {
                            nmap: 'Nmap',
                            zap: 'OWASP ZAP',
                            openvas: 'OpenVAS',
                            nuclei: 'Nuclei',
                            sslyze: 'SSLyze',
                          };
                          return (
                            <span key={tool} className="px-3 py-1.5 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-600">
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
                    className="flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-700 hover:to-teal-700 text-white font-bold py-3 px-6 rounded-xl shadow-lg shadow-emerald-600/30 transition-all transform hover:scale-105 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span className="material-symbols-outlined text-lg">
                      {isSubmitting ? 'hourglass_empty' : 'play_arrow'}
                    </span>
                    <span>{isSubmitting ? 'Starting Scan...' : 'Start Scan'}</span>
                  </button>
                  <button
                    onClick={() => setShowNewScanForm(false)}
                    disabled={isSubmitting}
                    className="flex items-center justify-center gap-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white font-bold py-3 px-6 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
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
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Scan Name</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Target</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Status</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Risk Level</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Vulns</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Date</th>
                        <th className="py-4 px-6 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                      {scans.map((scan) => (
                        <tr key={scan.id} className="group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150">
                          <td className="py-4 px-6">
                            <p className="text-slate-900 dark:text-white font-semibold text-sm">{scan.name}</p>
                          </td>
                          <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm">{scan.target}</td>
                          <td className="py-4 px-6 whitespace-nowrap">
                            <span className={`inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-bold ${scan.statusColor}`}>
                              {scan.status}
                            </span>
                          </td>
                          <td className="py-4 px-6">
                            <span className={`text-sm font-bold ${scan.riskColor}`}>{scan.riskLevel}</span>
                          </td>
                          <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm font-mono font-bold">{scan.vulnerabilities}</td>
                          <td className="py-4 px-6 text-slate-700 dark:text-slate-300 text-sm">{scan.date}</td>
                          <td className="py-4 px-6 text-right whitespace-nowrap">
                            <button 
                              onClick={() => setSelectedScanDetails(scan)}
                              className="text-slate-400 dark:text-slate-500 hover:text-white dark:hover:text-white hover:bg-slate-700 dark:hover:bg-slate-600 p-2 rounded-lg transition-all transform hover:scale-110"
                            >
                              <span className="material-symbols-outlined text-[20px]">more_vert</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="bg-slate-100 dark:bg-slate-700/30 border-t border-slate-200 dark:border-slate-700 px-6 py-4 flex items-center justify-between">
                  <p className="text-sm text-slate-600 dark:text-slate-400 font-medium">
                    Showing <span className="text-slate-900 dark:text-white font-bold">1-3</span> of <span className="text-slate-900 dark:text-white font-bold">12</span> scans
                  </p>
                  <div className="flex items-center gap-2.5">
                    <button className="p-2 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed">
                      <span className="material-symbols-outlined">chevron_left</span>
                    </button>
                    <button className="p-2 rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-all">
                      <span className="material-symbols-outlined">chevron_right</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    

      {/* Scan Details Modal */}
      {selectedScanDetails && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-2xl w-full max-w-3xl my-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-700">
              <div>
                <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
                  {selectedScanDetails.name}
                </h2>
                <p className="text-slate-600 dark:text-slate-400 text-sm mt-1">
                  Scan Details & Metadata
                </p>
              </div>
              <button
                onClick={() => setSelectedScanDetails(null)}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
              >
                <span className="material-symbols-outlined text-2xl">close</span>
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 max-h-[70vh] overflow-y-auto">
              {/* Risks Overview */}
              <div className="mb-8">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Risks Overview</h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  <div className="bg-red-50 dark:bg-red-500/10 rounded-lg p-4 border border-red-200 dark:border-red-500/30">
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">0</p>
                    <p className="text-xs text-red-600 dark:text-red-400 font-semibold">Critical</p>
                  </div>
                  <div className="bg-orange-50 dark:bg-orange-500/10 rounded-lg p-4 border border-orange-200 dark:border-orange-500/30">
                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">0</p>
                    <p className="text-xs text-orange-600 dark:text-orange-400 font-semibold">High</p>
                  </div>
                  <div className="bg-yellow-50 dark:bg-yellow-500/10 rounded-lg p-4 border border-yellow-200 dark:border-yellow-500/30">
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{selectedScanDetails.vulnerabilities}</p>
                    <p className="text-xs text-yellow-600 dark:text-yellow-400 font-semibold">Medium</p>
                  </div>
                  <div className="bg-blue-50 dark:bg-blue-500/10 rounded-lg p-4 border border-blue-200 dark:border-blue-500/30">
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">0</p>
                    <p className="text-xs text-blue-600 dark:text-blue-400 font-semibold">Low</p>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-500/10 rounded-lg p-4 border border-slate-200 dark:border-slate-500/30">
                    <p className="text-2xl font-bold text-slate-600 dark:text-slate-400">0</p>
                    <p className="text-xs text-slate-600 dark:text-slate-400 font-semibold">Info</p>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mb-8">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">Scan Progress</h3>
                  <span className="text-sm font-bold text-slate-600 dark:text-slate-400">{selectedScanDetails.progress}%</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-3 overflow-hidden">
                  <div 
                    className="bg-gradient-to-r from-blue-500 to-cyan-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${selectedScanDetails.progress}%` }}
                  />
                </div>
              </div>

              {/* Metadata */}
              <div className="mb-8">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Scan Metadata</h3>
                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-4 pb-3 border-b border-slate-200 dark:border-slate-700">
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">ID</p>
                      <p className="text-sm font-mono text-slate-900 dark:text-white break-all">{selectedScanDetails.id}</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Type</p>
                      <p className="text-sm font-semibold text-slate-900 dark:text-white">Full Scan</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Status</p>
                      <span className={`inline-flex items-center px-3 py-1 rounded-lg text-xs font-bold ${selectedScanDetails.statusColor}`}>
                        {selectedScanDetails.status}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 py-3 border-b border-slate-200 dark:border-slate-700">
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Target</p>
                      <p className="text-sm text-slate-900 dark:text-white font-medium">{selectedScanDetails.target}</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Risk Level</p>
                      <span className={`text-sm font-bold ${selectedScanDetails.riskColor}`}>{selectedScanDetails.riskLevel}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 py-3 border-b border-slate-200 dark:border-slate-700">
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Created At</p>
                      <p className="text-sm text-slate-900 dark:text-white">{selectedScanDetails.date}</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Updated At</p>
                      <p className="text-sm text-slate-900 dark:text-white">{selectedScanDetails.date}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 py-3">
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Is Agent</p>
                      <p className="text-sm text-slate-900 dark:text-white font-medium">false</p>
                    </div>
                    <div>
                      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-1">Total Vulnerabilities</p>
                      <p className="text-sm text-slate-900 dark:text-white font-bold">{selectedScanDetails.vulnerabilities}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Vulnerabilities Found */}
              {selectedScanDetails.vulnerabilities > 0 && (
                <div>
                  <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Vulnerabilities Found</h3>
                  <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                      {selectedScanDetails.vulnerabilities} vulnerability item(s) detected during scan execution
                    </p>
                    <div className="mt-4 space-y-2">
                      {[...Array(Math.min(selectedScanDetails.vulnerabilities, 3))].map((_, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 bg-white dark:bg-slate-700/30 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="material-symbols-outlined text-amber-600 dark:text-amber-400 text-lg mt-1">warning</span>
                          <div>
                            <p className="text-sm font-semibold text-slate-900 dark:text-white">Medium Severity Issue #{i + 1}</p>
                            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">CVSS Score: 5.{i}</p>
                          </div>
                        </div>
                      ))}
                      {selectedScanDetails.vulnerabilities > 3 && (
                        <p className="text-xs text-slate-600 dark:text-slate-400 text-center py-2">
                          +{selectedScanDetails.vulnerabilities - 3} more vulnerabilities
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
              <button
                onClick={() => setSelectedScanDetails(null)}
                className="px-6 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-900 dark:text-white font-semibold rounded-lg transition-all"
              >
                Close
              </button>
              <button className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-all">
                Export Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
)}