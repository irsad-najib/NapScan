'use client';

import { useState } from 'react';

export default function ScanConfigurationPage() {
  const [target, setTarget] = useState('');
  const [description, setDescription] = useState('');
  const [selectedTools, setSelectedTools] = useState(['nmap', 'owasp-zap']);
  const [frequency, setFrequency] = useState('One-time Scan (Immediate)');
  const [scanCompletionNotif, setScanCompletionNotif] = useState(true);
  const [criticalRisksNotif, setCriticalRisksNotif] = useState(false);

  const tools = [
    {
      id: 'nmap',
      name: 'Nmap',
      description: 'Network discovery and security auditing tool.',
      icon: 'radar',
    },
    {
      id: 'openvas',
      name: 'OpenVAS',
      description: 'Full-featured vulnerability scanner.',
      icon: 'bug_report',
    },
    {
      id: 'owasp-zap',
      name: 'OWASP ZAP',
      description: 'Web application security scanner.',
      icon: 'shield',
    },
    {
      id: 'sslyze',
      name: 'SSLyze',
      description: 'Fast and comprehensive SSL/TLS configuration analysis.',
      icon: 'lock',
    },
  ];

  const toggleTool = (toolId: string) => {
    setSelectedTools((prev) =>
      prev.includes(toolId) ? prev.filter((id) => id !== toolId) : [...prev, toolId]
    );
  };

  return (
    <div className="bg-background-light dark:bg-background-dark min-h-screen flex flex-col font-display text-slate-900 dark:text-white overflow-x-hidden">
      {/* Header / Breadcrumbs Area */}
      <div className="w-full border-b border-[#324467] bg-[#192233]/50 backdrop-blur-sm sticky top-0 z-20">
        <div className="px-6 lg:px-12 py-4 max-w-[1440px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <a className="text-[#92a4c9] text-sm font-medium hover:text-white transition-colors" href="#">
              Home
            </a>
            <span className="material-symbols-outlined text-[#92a4c9] text-sm">chevron_right</span>
            <a className="text-[#92a4c9] text-sm font-medium hover:text-white transition-colors" href="#">
              Scans
            </a>
            <span className="material-symbols-outlined text-[#92a4c9] text-sm">chevron_right</span>
            <span className="text-white text-sm font-medium">New Configuration</span>
          </div>
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-[#324467] hover:bg-[#324467]/30 transition text-sm text-[#92a4c9]">
              <span className="material-symbols-outlined text-[18px]">folder_open</span>
              Load Preset
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="px-6 lg:px-12 py-8 flex flex-1 justify-center">
        <div className="flex flex-col lg:flex-row gap-8 max-w-[1440px] w-full">
          {/* Left Column: Configuration Form */}
          <div className="flex-1 flex flex-col gap-8 min-w-0">
            {/* Page Heading */}
            <div className="flex flex-col gap-2">
              <h1 className="text-white text-3xl md:text-4xl font-black leading-tight tracking-[-0.033em]">
                New Scan Configuration
              </h1>
              <p className="text-[#92a4c9] text-base font-normal leading-normal max-w-2xl">
                Configure your security scan parameters, select specialized tools, and define notification rules for risk
                management.
              </p>
            </div>

            {/* Target Definition Section */}
            <div className="flex flex-col gap-4 bg-[#192233] p-6 rounded-xl border border-[#324467]">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <span className="material-symbols-outlined text-primary">hub</span>
                </div>
                <h2 className="text-white text-xl font-bold">Target Definition</h2>
              </div>
              <div className="flex flex-col gap-4">
                <label className="flex flex-col flex-1">
                  <span className="text-white text-sm font-medium pb-2">Target IP, Domain, or CIDR</span>
                  <div className="relative">
                    <span className="absolute left-4 top-1/2 -translate-y-1/2 material-symbols-outlined text-[#92a4c9]">
                      language
                    </span>
                    <input
                      className="w-full rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary/50 border border-[#324467] bg-[#111722] h-12 pl-12 pr-4 placeholder:text-[#92a4c9] text-base font-normal transition-all"
                      placeholder="e.g. 192.168.1.1 or example.com"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                    />
                  </div>
                  <p className="text-[#92a4c9] text-xs mt-2 pl-1">Supports IPv4, IPv6, and standard domain formats.</p>
                </label>
                <label className="flex flex-col flex-1">
                  <span className="text-white text-sm font-medium pb-2">Description (Optional)</span>
                  <textarea
                    className="w-full rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary/50 border border-[#324467] bg-[#111722] min-h-[80px] p-4 placeholder:text-[#92a4c9] text-base font-normal resize-y transition-all"
                    placeholder="Add context for this scan..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </label>
              </div>
            </div>

            {/* Scanner Tools Section */}
            <div className="flex flex-col gap-4">
              <h2 className="text-white text-xl font-bold px-1">Select Scanner Tools</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {tools.map((tool) => (
                  <label key={tool.id} className="relative cursor-pointer group">
                    <input
                      checked={selectedTools.includes(tool.id)}
                      onChange={() => toggleTool(tool.id)}
                      className="peer sr-only"
                      type="checkbox"
                    />
                    <div className="p-5 rounded-xl border border-[#324467] bg-[#192233] hover:border-primary/50 peer-checked:border-primary peer-checked:bg-primary/5 transition-all h-full flex flex-col gap-3">
                      <div className="flex justify-between items-start">
                        <div className="p-2 rounded-lg bg-[#25334d] text-[#92a4c9] peer-checked:bg-primary peer-checked:text-white transition-colors">
                          <span className="material-symbols-outlined">{tool.icon}</span>
                        </div>
                        <span className="material-symbols-outlined text-primary opacity-0 peer-checked:opacity-100 transition-opacity">
                          check_circle
                        </span>
                      </div>
                      <div>
                        <p className="text-white font-bold text-lg">{tool.name}</p>
                        <p className="text-[#92a4c9] text-sm mt-1">{tool.description}</p>
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Schedule & Notifications Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Schedule Section */}
              <div className="flex flex-col gap-4 bg-[#192233] p-6 rounded-xl border border-[#324467]">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <span className="material-symbols-outlined text-primary">calendar_clock</span>
                  </div>
                  <h2 className="text-white text-lg font-bold">Schedule</h2>
                </div>
                <label className="flex flex-col w-full">
                  <span className="text-white text-sm font-medium pb-2">Frequency</span>
                  <select
                    value={frequency}
                    onChange={(e) => setFrequency(e.target.value)}
                    className="w-full rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary/50 border border-[#324467] bg-[#111722] h-11 px-4 text-sm font-normal"
                  >
                    <option>One-time Scan (Immediate)</option>
                    <option>Daily</option>
                    <option>Weekly</option>
                    <option>Monthly</option>
                  </select>
                </label>
                <label className="flex flex-col w-full opacity-50 cursor-not-allowed pointer-events-none">
                  <span className="text-white text-sm font-medium pb-2">Start Time</span>
                  <input
                    className="w-full rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary/50 border border-[#324467] bg-[#111722] h-11 px-4 text-sm font-normal [color-scheme:dark]"
                    disabled
                    type="datetime-local"
                  />
                </label>
              </div>

              {/* Notifications Section */}
              <div className="flex flex-col gap-4 bg-[#192233] p-6 rounded-xl border border-[#324467]">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <span className="material-symbols-outlined text-primary">notifications_active</span>
                  </div>
                  <h2 className="text-white text-lg font-bold">Notifications</h2>
                </div>

                {/* Notification Item 1 */}
                <div className="flex items-center justify-between py-2">
                  <div className="flex flex-col">
                    <span className="text-white text-sm font-medium">Scan Completion</span>
                    <span className="text-[#92a4c9] text-xs">Email report when finished</span>
                  </div>
                  <label className="inline-flex items-center cursor-pointer">
                    <input
                      checked={scanCompletionNotif}
                      onChange={(e) => setScanCompletionNotif(e.target.checked)}
                      className="sr-only peer"
                      type="checkbox"
                    />
                    <div className="relative w-11 h-6 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary"></div>
                  </label>
                </div>

                {/* Notification Item 2 */}
                <div className="flex items-center justify-between py-2 border-t border-[#324467]">
                  <div className="flex flex-col">
                    <span className="text-white text-sm font-medium">Critical Risks</span>
                    <span className="text-[#92a4c9] text-xs">Instant Alert via Slack</span>
                  </div>
                  <label className="inline-flex items-center cursor-pointer">
                    <input
                      checked={criticalRisksNotif}
                      onChange={(e) => setCriticalRisksNotif(e.target.checked)}
                      className="sr-only peer"
                      type="checkbox"
                    />
                    <div className="relative w-11 h-6 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-primary"></div>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Summary & Actions Sticky Sidebar */}
          <div className="w-full lg:w-[360px] flex flex-col gap-6 shrink-0">
            <div className="lg:sticky lg:top-24 flex flex-col gap-6">
              {/* Summary Card */}
              <div className="bg-[#192233] rounded-xl border border-[#324467] overflow-hidden">
                <div className="p-6 border-b border-[#324467]">
                  <h3 className="text-white text-lg font-bold">Configuration Summary</h3>
                </div>
                <div className="p-6 flex flex-col gap-4">
                  <div className="flex justify-between items-center">
                    <span className="text-[#92a4c9] text-sm">Scan Type</span>
                    <span className="text-white text-sm font-medium">Infrastructure & Web</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#92a4c9] text-sm">Tools Selected</span>
                    <span className="text-white text-sm font-medium">
                      {selectedTools.length} / {tools.length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#92a4c9] text-sm">Target Type</span>
                    <span className="text-white text-sm font-medium">{target ? 'Defined' : 'Undefined'}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-[#92a4c9] text-sm">Frequency</span>
                    <span className="text-white text-sm font-medium">
                      {frequency === 'One-time Scan (Immediate)' ? 'Immediate' : frequency}
                    </span>
                  </div>
                  <div className="h-px w-full bg-[#324467] my-2"></div>
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-1.5 text-[#92a4c9]">
                      <span className="material-symbols-outlined text-sm">timer</span>
                      <span className="text-sm">Est. Duration</span>
                    </div>
                    <span className="text-white text-sm font-medium">~ 45 mins</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="p-4 bg-[#111722] flex flex-col gap-3">
                  <button className="w-full bg-primary hover:bg-blue-600 text-white font-bold py-3.5 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(19,91,236,0.3)]">
                    <span className="material-symbols-outlined">play_arrow</span>
                    Run Scan
                  </button>
                  <button className="w-full bg-transparent border border-[#324467] hover:bg-[#324467] text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined text-[#92a4c9]">save</span>
                    Save Configuration
                  </button>
                </div>
              </div>

              {/* Help / Tip Card */}
              <div className="bg-gradient-to-br from-[#192233] to-[#111722] p-5 rounded-xl border border-[#324467]/50 relative overflow-hidden">
                {/* Decorative background pattern */}
                <div className="absolute -right-6 -top-6 w-24 h-24 bg-primary/10 rounded-full blur-2xl"></div>
                <div className="flex gap-3 relative z-10">
                  <span className="material-symbols-outlined text-primary mt-1">info</span>
                  <div>
                    <h4 className="text-white font-bold text-sm mb-1">Scanning Advice</h4>
                    <p className="text-[#92a4c9] text-xs leading-relaxed">
                      Using <strong>OWASP ZAP</strong> can significantly increase scan duration. For a quick check, stick to
                      Nmap and OpenVAS first.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
