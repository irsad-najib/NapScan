import React, { useMemo } from 'react';
import { ToolKey } from '@/services/api';

interface ParsedResultTableProps {
    tool: ToolKey | string;
    data: any[];
    type?: string;
    status?: string;
}

export function ParsedResultTable({ tool, data, type, status }: ParsedResultTableProps) {
    interface ColumnDef {
        header: string;
        accessor: string;
        className?: string;
    }

    // Memoize columns definition to avoid unnecessary re-renders
    const columns = useMemo<ColumnDef[]>(() => {
        if (!data || data.length === 0) return [];

        switch (tool) {
            case 'nmap':
                return [
                    { header: 'Port', accessor: 'port', className: 'w-24 font-mono' },
                    { header: 'Protocol', accessor: 'protocol', className: 'w-24 uppercase text-xs font-bold' },
                    { header: 'Severity', accessor: 'severity', className: 'w-24' },
                    { header: 'State', accessor: 'state', className: 'w-32 capitalize' },
                    { header: 'Service', accessor: 'service', className: 'font-medium' },
                    { header: 'Version', accessor: 'version', className: 'text-slate-500 hidden md:table-cell' },
                ];
            case 'ffuf':
                return [
                    { header: 'Path', accessor: 'path', className: 'font-mono text-blue-600 dark:text-blue-400' },
                    { header: 'Status', accessor: 'status', className: 'w-24 font-bold' },
                    { header: 'Size', accessor: 'size', className: 'w-24 text-right font-mono text-xs' },
                    { header: 'Words', accessor: 'words', className: 'w-24 text-right font-mono text-xs hidden sm:table-cell' },
                    { header: 'Lines', accessor: 'lines', className: 'w-24 text-right font-mono text-xs hidden md:table-cell' },
                ];
            case 'zap':
                return [
                    { header: 'Alert', accessor: 'alert', className: 'font-medium' },
                    { header: 'Risk', accessor: 'risk', className: 'w-32' },
                    { header: 'Confidence', accessor: 'confidence', className: 'w-32 hidden sm:table-cell' },
                    { header: 'Method', accessor: 'method', className: 'w-24 uppercase font-mono text-xs' },
                    { header: 'URL', accessor: 'url', className: 'text-xs text-slate-500 truncate max-w-xs' },
                ];
            case 'nuclei':
                return [
                    { header: 'Template', accessor: 'template', className: 'font-mono text-xs' },
                    { header: 'Severity', accessor: 'severity', className: 'w-32' },
                    { header: 'Name', accessor: 'name', className: 'font-medium' },
                    { header: 'Matched At', accessor: 'matched_at', className: 'text-xs text-slate-500 break-all' },
                ];
            case 'sslyze':
                return [
                    { header: 'Property', accessor: 'property', className: 'font-medium w-64' },
                    { header: 'Value', accessor: 'value', className: 'text-sm' },
                    { header: 'Status', accessor: 'status', className: 'w-32 text-right' },
                ];
            case 'openvas':
                return [
                    { header: 'Vulnerability', accessor: 'name', className: 'font-medium' },
                    { header: 'Severity', accessor: 'severity', className: 'w-32' },
                    { header: 'Host', accessor: 'host', className: 'w-32 font-mono text-xs' },
                    { header: 'Port', accessor: 'port', className: 'w-24 font-mono text-xs' },
                ];
            case 'mobsf':
                return [
                    { header: 'Vulnerability', accessor: 'title', className: 'font-medium' },
                    { header: 'Severity', accessor: 'severity', className: 'w-32' },
                    { header: 'Description', accessor: 'description', className: 'text-xs text-slate-500 line-clamp-2' },
                ];
            default:
                // Try to infer columns from first item
                const keys = Object.keys(data[0] || {});
                return keys.map(key => ({
                    header: key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' '),
                    accessor: key
                }));
        }
    }, [tool, data, type]);

    if (!data) return null;

    const [filterValue, setFilterValue] = React.useState<string>('all');

    // Extract unique filter values based on tool type
    const filterOptions = useMemo(() => {
        if (!data || data.length === 0) return [];

        let field = '';
        switch (tool) {
            case 'zap': field = 'risk'; break;
            case 'nuclei': field = 'severity'; break;
            case 'nmap': field = 'severity'; break;
            case 'ffuf': field = 'status'; break;
            case 'openvas': field = 'severity'; break;
            case 'mobsf': field = 'severity'; break;
            case 'sslyze': field = 'status'; break;
            default: return [];
        }

        const values = new Set(data.map(item => String(item[field] || '')));
        return Array.from(values).sort();
    }, [data, tool]);

    const filteredData = useMemo(() => {
        if (filterValue === 'all') return data;

        let field = '';
        switch (tool) {
            case 'zap': field = 'risk'; break;
            case 'nuclei': field = 'severity'; break;
            case 'nmap': field = 'severity'; break;
            case 'ffuf': field = 'status'; break;
            case 'openvas': field = 'severity'; break;
            case 'mobsf': field = 'severity'; break;
            case 'sslyze': field = 'status'; break;
            default: return data;
        }

        return data.filter(item => String(item[field] || '') === filterValue);
    }, [data, filterValue, tool]);

    // Error State Handling
    if (status === 'failed') {
        return (
            <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-red-50 to-orange-50 dark:from-red-900/10 dark:to-orange-900/10 p-12 text-center border border-red-200 dark:border-red-800">
                <div className="relative z-10 space-y-3">
                    <div className="mx-auto w-16 h-16 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4">
                        <span className="material-symbols-outlined text-3xl text-red-600 dark:text-red-400">
                            error
                        </span>
                    </div>
                    <h3 className="text-xl font-bold text-red-900 dark:text-red-200">
                        Scan Failed
                    </h3>
                    <p className="text-red-700 dark:text-red-300 max-w-sm mx-auto text-sm">
                        The scan encountered an error and could not complete successfully. Please check the raw output for more details.
                    </p>
                </div>
            </div>
        );
    }

    if (!data || data.length === 0) {
        if (status?.toLowerCase() === 'running' || status?.toLowerCase() === 'pending') {
            return (
                <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-50 to-white dark:from-slate-900 dark:to-slate-800 p-12 text-center border border-slate-200 dark:border-slate-800 group">
                    {/* Background Decor */}
                    <div className="absolute top-0 left-0 w-full h-full overflow-hidden opacity-50 pointer-events-none">
                        <div className="absolute top-10 right-10 w-24 h-24 bg-blue-500/5 rounded-full blur-2xl animate-pulse"></div>
                        <div className="absolute bottom-10 left-10 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl animate-pulse delay-700"></div>
                    </div>

                    {/* Icon wrapper with glow effect */}
                    <div className="relative mx-auto w-24 h-24 mb-6">
                        <div className="absolute inset-0 bg-blue-500/20 rounded-full blur-xl animate-pulse"></div>
                        <div className="relative w-full h-full bg-gradient-to-br from-white to-blue-50 dark:from-slate-800 dark:to-slate-900 rounded-full flex items-center justify-center border-2 border-blue-100 dark:border-blue-900 shadow-xl">
                            <span className="material-symbols-outlined text-5xl text-blue-500 dark:text-blue-400 drop-shadow-sm animate-bounce-slow">
                                search
                            </span>
                        </div>

                        {/* Orbiting particles */}
                        <div className="absolute inset-0 animate-spin-slow">
                            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-blue-400 rounded-full opacity-60"></div>
                            <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1.5 h-1.5 bg-cyan-400 rounded-full opacity-40"></div>
                        </div>
                    </div>

                    {/* Text content */}
                    <div className="relative z-10 space-y-3">
                        <h3 className="text-2xl font-bold bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                            Scan in Progress
                        </h3>
                        <p className="text-slate-600 dark:text-slate-400 max-w-md mx-auto leading-relaxed text-base">
                            We are currently analyzing the target. Please wait while the scan completes.
                        </p>
                    </div>
                </div>
            );
        }

        return (
            <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-50 to-white dark:from-slate-900 dark:to-slate-800 p-12 text-center border border-slate-200 dark:border-slate-800 group">
                {/* Background Decor */}
                <div className="absolute top-0 left-0 w-full h-full overflow-hidden opacity-50 pointer-events-none">
                    <div className="absolute top-10 left-10 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl group-hover:bg-emerald-500/10 transition-colors duration-500"></div>
                    <div className="absolute bottom-10 right-10 w-32 h-32 bg-teal-500/5 rounded-full blur-2xl group-hover:bg-teal-500/10 transition-colors duration-500"></div>
                </div>

                {/* Icon wrapper with glow effect */}
                <div className="relative mx-auto w-24 h-24 mb-6">
                    <div className="absolute inset-0 bg-emerald-500/20 rounded-full blur-xl animate-pulse"></div>
                    <div className="relative w-full h-full bg-gradient-to-br from-white to-emerald-50 dark:from-slate-800 dark:to-slate-900 rounded-full flex items-center justify-center border-2 border-emerald-100 dark:border-emerald-900 shadow-xl">
                        <span className="material-symbols-outlined text-5xl text-emerald-500 dark:text-emerald-400 drop-shadow-sm">
                            verified_user
                        </span>
                    </div>

                    {/* Floating check badge */}
                    <div className="absolute -bottom-2 -right-2 bg-gradient-to-br from-emerald-500 to-emerald-600 dark:from-emerald-400 dark:to-emerald-500 text-white p-2 rounded-full border-4 border-white dark:border-slate-900 flex items-center justify-center shadow-lg shadow-emerald-500/30 group-hover:scale-110 transition-transform duration-300 animate-bounce">
                        <span className="material-symbols-outlined text-base font-bold">check</span>
                    </div>

                    {/* Orbiting particles */}
                    <div className="absolute inset-0 animate-spin-slow">
                        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-emerald-400 rounded-full opacity-60"></div>
                        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1.5 h-1.5 bg-teal-400 rounded-full opacity-40"></div>
                    </div>
                </div>

                {/* Text content */}
                <div className="relative z-10 space-y-3">
                    <h3 className="text-2xl font-bold bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                        All Clear! No Issues Found
                    </h3>
                    <p className="text-slate-600 dark:text-slate-400 max-w-md mx-auto leading-relaxed text-base">
                        The security scan completed successfully with{" "}
                        <span className="font-semibold text-emerald-600 dark:text-emerald-400">zero vulnerabilities</span>{" "}
                        detected.
                    </p>

                    {/* Stats badges */}
                    <div className="flex items-center justify-center gap-4 pt-4">
                        <div className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-100 dark:bg-emerald-950/50 rounded-full border border-emerald-200 dark:border-emerald-800">
                            <span className="material-symbols-outlined text-emerald-600 dark:text-emerald-400 text-sm">shield</span>
                            <span className="text-xs font-semibold text-emerald-700 dark:text-emerald-300">Protected</span>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    const renderCell = (item: any, column: any) => {
        const value = item[column.accessor];

        // Custom rendering based on column/value
        if (column.accessor === 'state' || column.accessor === 'status') {
            let color = 'bg-slate-100 text-slate-700';
            const v = String(value).toLowerCase();
            if (v.includes('open') || v === '200') color = 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400';
            else if (v.includes('filtered') || v === '403') color = 'bg-orange-100 text-orange-700 dark:bg-orange-500/20 dark:text-orange-400';
            else if (v.includes('closed') || v === '404') color = 'bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-400';

            return (
                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${color}`}>
                    {value}
                </span>
            );
        }

        if (column.accessor === 'severity' || column.accessor === 'risk') {
            let color = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';
            const v = String(value).toLowerCase();

            if (v.includes('critical')) color = 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300';
            else if (v.includes('high')) color = 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300';
            else if (v.includes('medium')) color = 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300';
            else if (v.includes('low')) color = 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300';
            else if (v.includes('info')) color = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';

            return (
                <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wide ${color}`}>
                    {value}
                </span>
            );
        }

        return value;
    };

    return (
        <div className="space-y-4">
            {filterOptions.length > 0 && (
                <div className="flex items-center justify-end">
                    <div className="flex items-center gap-2">
                        <label htmlFor="severity-filter" className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Filter by Status:
                        </label>
                        <select
                            id="severity-filter"
                            value={filterValue}
                            onChange={(e) => setFilterValue(e.target.value)}
                            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white text-sm rounded-lg px-3 py-2 focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none transition-all"
                        >
                            <option value="all">All ({data.length})</option>
                            {filterOptions.map(opt => (
                                <option key={opt} value={opt}>
                                    {opt.charAt(0).toUpperCase() + opt.slice(1)} ({data.filter(d => {
                                        let field = '';
                                        switch (tool) {
                                            case 'zap': field = 'risk'; break;
                                            case 'nuclei': field = 'severity'; break;
                                            case 'nmap': field = 'severity'; break;
                                            case 'ffuf': field = 'status'; break;
                                            case 'openvas': field = 'severity'; break;
                                            case 'mobsf': field = 'severity'; break;
                                            case 'sslyze': field = 'status'; break;
                                        }
                                        return String(d[field] || '') === opt;
                                    }).length})
                                </option>
                            ))}
                        </select>
                    </div>
                </div>
            )}

            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
                <table className="w-full text-left text-sm whitespace-nowrap">
                    <thead className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                        <tr>
                            {columns.map((col) => (
                                <th key={col.accessor} className={`px-4 py-3 font-semibold text-slate-900 dark:text-white ${col.className || ''}`}>
                                    {col.header}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {filteredData.map((item, idx) => (
                            <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors" title={item.description || item.vulnerability || item.name || ""}>
                                {columns.map((col) => (
                                    <td key={`${idx}-${col.accessor}`} className={`px-4 py-3 text-slate-600 dark:text-slate-300 ${col.className || ''}`}>
                                        {renderCell(item, col)}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
