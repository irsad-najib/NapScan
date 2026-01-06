'use client';

import { useState } from 'react';

export default function TargetsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [newTarget, setNewTarget] = useState('');
  const [continuousMonitoring, setContinuousMonitoring] = useState(true);
  const [deepScan, setDeepScan] = useState(false);
  const [includeSubdomains, setIncludeSubdomains] = useState(false);
  const [statusFilter, setStatusFilter] = useState('All Statuses');

  const targets = [
    {
      id: 1,
      name: 'api.company-prod.com',
      description: 'Production API Gateway',
      icon: 'language',
      status: 'Scanning (45%)',
      statusType: 'scanning',
      riskScore: 'Analyzing...',
      riskLevel: null,
      vulnCount: null,
      lastScanned: 'Just now',
    },
    {
      id: 2,
      name: '192.168.10.55',
      description: 'Internal Database',
      icon: 'dns',
      status: 'Completed',
      statusType: 'completed',
      riskScore: '8.5',
      riskLevel: 'High',
      vulnCount: '3 Critical, 5 High',
      lastScanned: '2 hours ago',
    },
    {
      id: 3,
      name: 'staging.web.app',
      description: 'Staging Environment',
      icon: 'language',
      status: 'Idle',
      statusType: 'idle',
      riskScore: '2.1',
      riskLevel: 'Low',
      vulnCount: '0 Critical, 0 High',
      lastScanned: 'Oct 24, 2023',
    },
    {
      id: 4,
      name: 'aws-s3-backup-bucket',
      description: 'Cloud Storage',
      icon: 'cloud_queue',
      status: 'Scheduled',
      statusType: 'scheduled',
      riskScore: 'Pending scan...',
      riskLevel: null,
      vulnCount: null,
      lastScanned: 'Never',
    },
  ];

  const stats = [
    { label: 'Total Targets', value: '124', trend: '+5%', icon: 'target', color: 'primary' },
    { label: 'Active Scans', value: '3', trend: 'Running', icon: 'radar', color: 'blue', isBadge: true },
    { label: 'Critical Vulns', value: '12', trend: 'Action Needed', icon: 'bug_report', color: 'rose', isBadge: true },
  ];

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard' },
    { label: 'Targets', icon: 'target', active: true },
    { label: 'Scans', icon: 'radar' },
    { label: 'Reports', icon: 'description' },
    { label: 'Settings', icon: 'settings' },
  ];

  const getStatusBadgeColor = (statusType: string) => {
    switch (statusType) {
      case 'scanning':
        return 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20';
      case 'completed':
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20';
      case 'idle':
        return 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20';
      case 'scheduled':
        return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20';
      default:
        return '';
    }
  };

  const getRiskColor = (riskLevel: string | null) => {
    switch (riskLevel) {
      case 'High':
        return 'text-rose-500';
      case 'Low':
        return 'text-emerald-500';
      default:
        return 'text-slate-500';
    }
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background-light dark:bg-background-dark">
      {/* Sidebar */}
      <aside className="w-64 bg-background-dark border-r border-[#232f48] flex-col hidden md:flex shrink-0 transition-all duration-300">
        <div className="h-full flex flex-col justify-between p-4">
          <div className="flex flex-col gap-6">
            {/* Logo */}
            <div className="flex items-center gap-3 px-2">
              <div className="bg-primary/20 flex items-center justify-center aspect-square rounded-full size-10 text-primary">
                <span className="material-symbols-outlined text-2xl">shield_lock</span>
              </div>
              <h1 className="text-white text-lg font-bold leading-normal tracking-tight">SecScan Pro</h1>
            </div>

            {/* Nav Items */}
            <nav className="flex flex-col gap-2">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors group ${
                    item.active
                      ? 'bg-primary/10 border border-primary/20 text-primary'
                      : 'text-slate-400 hover:bg-[#232f48] hover:text-white'
                  }`}
                  href="#"
                >
                  <span className={`material-symbols-outlined ${item.active ? 'fill-current' : 'group-hover:text-primary'} transition-colors`}>
                    {item.icon}
                  </span>
                  <span className={`text-sm ${item.active ? 'font-bold' : 'font-medium'}`}>{item.label}</span>
                </a>
              ))}
            </nav>
          </div>

          {/* User Profile Bottom */}
          <div className="flex items-center gap-3 px-3 py-3 mt-auto rounded-lg hover:bg-[#232f48] cursor-pointer border-t border-[#232f48]/50 pt-4">
            <div
              className="bg-center bg-no-repeat bg-cover rounded-full size-8 shrink-0"
              style={{
                backgroundImage: `url("https://lh3.googleusercontent.com/aida-public/AB6AXuDa-VFRgn-smOSZhtUDbo1krQ-J-XX2bem17WBb9WUWciw7f38zXecG-ItvEW9FavSzaPwp9U7g_FCmEoXlrtTM98e3M0h1mAOtQNR_f4PCvcOa__Jv3M6TNt8wkb0dsbpIOddCl6KobOqzpM6kYrBZrrc6lzXi30KO4WHVBEt2_D6czQf1VyRIgQQsx5aPyEg90XF-EhJBH6NUCQbbIEW4oRD20yMIF1R0VxE0Jo1StIAmE1SfzZ7w3DApWJDBW2_Ry5UaQ3MgvULG")`,
              }}
            />
            <div className="flex flex-col min-w-0">
              <p className="text-white text-sm font-semibold truncate">Alex Morgan</p>
              <p className="text-slate-400 text-xs truncate">Security Analyst</p>
            </div>
            <span className="material-symbols-outlined text-slate-500 ml-auto text-lg">expand_more</span>
          </div>
        </div>
      </aside>

      {/* Main Layout */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-background-light dark:bg-background-dark relative">
        {/* Top Navigation */}
        <header className="h-16 flex items-center justify-between px-6 border-b border-[#232f48]/30 bg-background-light dark:bg-background-dark shrink-0 z-10">
          <button className="md:hidden text-slate-500 hover:text-primary">
            <span className="material-symbols-outlined">menu</span>
          </button>

          {/* Search */}
          <div className="hidden md:flex items-center bg-white dark:bg-[#1e293b] rounded-lg border border-slate-200 dark:border-[#324467] px-3 py-1.5 w-64 focus-within:ring-2 focus-within:ring-primary/50 transition-all">
            <span className="material-symbols-outlined text-slate-400 text-[20px]">search</span>
            <input
              className="bg-transparent border-none text-sm text-slate-700 dark:text-slate-200 placeholder-slate-400 focus:ring-0 w-full ml-2 h-6"
              placeholder="Search resources..."
              type="text"
            />
          </div>

          {/* Right Actions */}
          <div className="flex items-center gap-4 ml-auto">
            <button className="relative p-2 text-slate-500 hover:text-primary hover:bg-slate-100 dark:hover:bg-[#232f48] rounded-full transition-colors">
              <span className="material-symbols-outlined">notifications</span>
              <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border-2 border-background-light dark:border-background-dark"></span>
            </button>
            <button className="p-2 text-slate-500 hover:text-primary hover:bg-slate-100 dark:hover:bg-[#232f48] rounded-full transition-colors">
              <span className="material-symbols-outlined">help</span>
            </button>
            <div className="h-6 w-px bg-slate-300 dark:bg-[#324467]"></div>
            <button className="flex items-center gap-2 text-sm font-semibold text-slate-600 dark:text-slate-300 hover:text-primary transition-colors">
              <span>Docs</span>
              <span className="material-symbols-outlined text-lg">open_in_new</span>
            </button>
          </div>
        </header>

        {/* Main Content Scroll Area */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden p-6 md:p-10 scroll-smooth">
          <div className="max-w-6xl mx-auto flex flex-col gap-8 pb-20">
            {/* Breadcrumbs */}
            <div className="flex items-center gap-2 text-sm">
              <a className="text-slate-500 dark:text-[#92a4c9] hover:text-primary transition-colors" href="#">
                Home
              </a>
              <span className="material-symbols-outlined text-slate-600 text-[16px]">chevron_right</span>
              <span className="text-slate-800 dark:text-white font-medium">Targets</span>
            </div>

            {/* Page Header */}
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="flex flex-col gap-2">
                <h2 className="text-3xl md:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                  Target Management
                </h2>
                <p className="text-slate-500 dark:text-[#92a4c9] text-base md:text-lg">
                  Manage your attack surface by adding domains or IPs for automated scanning.
                </p>
              </div>
              <button className="flex items-center justify-center gap-2 bg-primary hover:bg-primary/90 text-white font-bold py-2.5 px-5 rounded-lg shadow-lg shadow-primary/20 transition-all transform active:scale-95 shrink-0 h-12">
                <span className="material-symbols-outlined">bolt</span>
                <span>Quick Scan</span>
              </button>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="bg-white dark:bg-[#151c2b] rounded-xl p-5 border border-slate-200 dark:border-[#324467] shadow-sm relative overflow-hidden group"
                >
                  <div className="absolute right-0 top-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                    <span
                      className={`material-symbols-outlined text-6xl ${
                        stat.color === 'primary' ? 'text-primary' : stat.color === 'blue' ? 'text-blue-500' : 'text-rose-500'
                      }`}
                    >
                      {stat.icon}
                    </span>
                  </div>
                  <p className="text-slate-500 dark:text-slate-400 text-sm font-medium mb-1">{stat.label}</p>
                  <div className="flex items-end gap-3">
                    <h3 className="text-3xl font-bold text-slate-900 dark:text-white">{stat.value}</h3>
                    <span
                      className={`text-sm font-bold px-2 py-0.5 rounded flex items-center mb-1 ${
                        stat.color === 'primary'
                          ? 'text-emerald-500 bg-emerald-500/10'
                          : stat.color === 'blue'
                            ? 'text-blue-500 bg-blue-500/10'
                            : 'text-rose-500 bg-rose-500/10'
                      }`}
                    >
                      {stat.isBadge ? (
                        stat.trend
                      ) : (
                        <>
                          <span className="material-symbols-outlined text-sm mr-1">trending_up</span>
                          {stat.trend}
                        </>
                      )}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Add Target Section */}
            <div className="bg-white dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-[#324467] shadow-sm p-6 flex flex-col gap-6">
              <div className="flex items-center gap-2 mb-1">
                <span className="material-symbols-outlined text-primary">add_circle</span>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Add New Target</h3>
              </div>
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1 relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 material-symbols-outlined">
                    link
                  </span>
                  <input
                    className="w-full h-12 pl-10 pr-4 rounded-lg bg-slate-50 dark:bg-[#101622] border border-slate-300 dark:border-[#324467] text-slate-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent outline-none transition-all placeholder:text-slate-400 dark:placeholder:text-slate-500"
                    placeholder="Enter domain (e.g. example.com) or IP address..."
                    type="text"
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                  />
                </div>
                <button className="h-12 px-6 bg-primary hover:bg-primary/90 text-white font-bold rounded-lg transition-colors flex items-center justify-center gap-2 whitespace-nowrap shadow-lg shadow-primary/20">
                  <span>Add Target</span>
                  <span className="material-symbols-outlined text-lg">arrow_forward</span>
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-6 pt-2 border-t border-slate-100 dark:border-[#324467]/50">
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input
                    checked={continuousMonitoring}
                    onChange={(e) => setContinuousMonitoring(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-primary focus:ring-primary bg-slate-100 dark:bg-[#101622] dark:border-[#324467]"
                    type="checkbox"
                  />
                  <span className="text-sm font-medium text-slate-600 dark:text-slate-300 group-hover:text-primary transition-colors">
                    Continuous Monitoring
                  </span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input
                    checked={deepScan}
                    onChange={(e) => setDeepScan(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-primary focus:ring-primary bg-slate-100 dark:bg-[#101622] dark:border-[#324467]"
                    type="checkbox"
                  />
                  <span className="text-sm font-medium text-slate-600 dark:text-slate-300 group-hover:text-primary transition-colors">
                    Deep Scan (Slower)
                  </span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input
                    checked={includeSubdomains}
                    onChange={(e) => setIncludeSubdomains(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-primary focus:ring-primary bg-slate-100 dark:bg-[#101622] dark:border-[#324467]"
                    type="checkbox"
                  />
                  <span className="text-sm font-medium text-slate-600 dark:text-slate-300 group-hover:text-primary transition-colors">
                    Include Subdomains
                  </span>
                </label>
              </div>
            </div>

            {/* Targets Table Section */}
            <div className="flex flex-col gap-4">
              {/* Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-4">
                <h3 className="text-xl font-bold text-slate-900 dark:text-white">All Targets</h3>
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-[18px]">
                      filter_list
                    </span>
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="h-9 pl-9 pr-8 bg-white dark:bg-[#1e293b] border border-slate-200 dark:border-[#324467] rounded-lg text-sm text-slate-700 dark:text-slate-200 focus:ring-1 focus:ring-primary outline-none cursor-pointer appearance-none"
                    >
                      <option>All Statuses</option>
                      <option>Scanning</option>
                      <option>Completed</option>
                      <option>Idle</option>
                      <option>Scheduled</option>
                    </select>
                  </div>
                  <button className="h-9 px-3 bg-white dark:bg-[#1e293b] border border-slate-200 dark:border-[#324467] rounded-lg text-sm text-slate-700 dark:text-slate-200 hover:border-primary transition-colors flex items-center gap-2">
                    <span className="material-symbols-outlined text-[18px]">download</span>
                    <span>Export</span>
                  </button>
                </div>
              </div>

              {/* Table Container */}
              <div className="bg-white dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-[#324467] shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50 dark:bg-[#151c2b] border-b border-slate-200 dark:border-[#324467]">
                        <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-[#92a4c9]">
                          Target
                        </th>
                        <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-[#92a4c9]">
                          Status
                        </th>
                        <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-[#92a4c9]">
                          Risk Score
                        </th>
                        <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-[#92a4c9]">
                          Last Scanned
                        </th>
                        <th className="py-4 px-6 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-[#92a4c9] text-right">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-[#324467]">
                      {targets.map((target) => (
                        <tr key={target.id} className="group hover:bg-slate-50 dark:hover:bg-[#232f48]/50 transition-colors">
                          <td className="py-4 px-6">
                            <div className="flex items-center gap-3">
                              <div className="bg-slate-100 dark:bg-[#101622] p-2 rounded text-slate-500 dark:text-slate-400">
                                <span className="material-symbols-outlined text-[20px]">{target.icon}</span>
                              </div>
                              <div>
                                <p className="text-sm font-bold text-slate-900 dark:text-white">{target.name}</p>
                                <p className="text-xs text-slate-500 dark:text-slate-400">{target.description}</p>
                              </div>
                            </div>
                          </td>
                          <td className="py-4 px-6">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusBadgeColor(target.statusType)}`}>
                              {target.statusType === 'scanning' && (
                                <span className="relative flex h-2 w-2">
                                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                                  <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
                                </span>
                              )}
                              {target.statusType === 'completed' && <span className="material-symbols-outlined text-[16px]">check_circle</span>}
                              {target.statusType === 'idle' && <span className="material-symbols-outlined text-[16px]">pause_circle</span>}
                              {target.statusType === 'scheduled' && <span className="material-symbols-outlined text-[16px]">schedule</span>}
                              {target.status}
                            </span>
                          </td>
                          <td className="py-4 px-6">
                            {target.statusType === 'scanning' ? (
                              <div className="flex items-center gap-2">
                                <div className="w-24 h-2 bg-slate-200 dark:bg-[#101622] rounded-full overflow-hidden">
                                  <div className="h-full bg-slate-400 animate-pulse w-1/2"></div>
                                </div>
                                <span className="text-xs text-slate-500">Analyzing...</span>
                              </div>
                            ) : target.statusType === 'scheduled' ? (
                              <span className="text-sm text-slate-400 italic">Pending scan...</span>
                            ) : (
                              <div className="flex flex-col">
                                <div className="flex items-center gap-2">
                                  <span className={`text-sm font-bold ${getRiskColor(target.riskLevel)}`}>{target.riskLevel}</span>
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      target.riskLevel === 'High'
                                        ? 'bg-rose-500/20 text-rose-500'
                                        : 'bg-emerald-500/20 text-emerald-500'
                                    }`}
                                  >
                                    {target.riskScore}
                                  </span>
                                </div>
                                <p className="text-[10px] text-slate-500 mt-0.5">{target.vulnCount}</p>
                              </div>
                            )}
                          </td>
                          <td className="py-4 px-6">
                            <p className="text-sm text-slate-600 dark:text-slate-300">{target.lastScanned}</p>
                          </td>
                          <td className="py-4 px-6 text-right">
                            {target.statusType === 'scanning' ? (
                              <button className="text-slate-400 hover:text-white hover:bg-red-500 p-1.5 rounded transition-all">
                                <span className="material-symbols-outlined text-[20px]">stop_circle</span>
                              </button>
                            ) : (
                              <>
                                <button className="text-slate-400 hover:text-white hover:bg-primary p-1.5 rounded transition-all mr-1">
                                  <span className="material-symbols-outlined text-[20px]">play_arrow</span>
                                </button>
                                <button className="text-slate-400 hover:text-white hover:bg-[#324467] p-1.5 rounded transition-all">
                                  <span className="material-symbols-outlined text-[20px]">more_vert</span>
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
                <div className="bg-slate-50 dark:bg-[#151c2b] border-t border-slate-200 dark:border-[#324467] px-6 py-3 flex items-center justify-between">
                  <p className="text-sm text-slate-500 dark:text-slate-400">Showing 1 to 4 of 124 entries</p>
                  <div className="flex items-center gap-2">
                    <button
                      disabled
                      className="px-3 py-1 text-sm rounded border border-slate-300 dark:border-[#324467] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#232f48] disabled:opacity-50"
                    >
                      Previous
                    </button>
                    <button className="px-3 py-1 text-sm rounded border border-slate-300 dark:border-[#324467] text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-[#232f48]">
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
