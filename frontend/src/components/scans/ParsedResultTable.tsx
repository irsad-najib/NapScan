import React, { useMemo } from 'react';
import { ToolKey } from '@/services/api';

interface ParsedResultTableProps {
    tool: ToolKey | string;
    data: any[];
    type?: string;
}

export function ParsedResultTable({ tool, data, type }: ParsedResultTableProps) {
    // Memoize columns definition to avoid unnecessary re-renders
    const columns = useMemo(() => {
        if (!data || data.length === 0) return [];

        switch (tool) {
            case 'nmap':
                return [
                    { header: 'Port', accessor: 'port', className: 'w-24 font-mono' },
                    { header: 'Protocol', accessor: 'protocol', className: 'w-24 uppercase text-xs font-bold' },
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
            case 'mobsf':
                // MobSF might have different tables for different sections
                if (type === 'permissions') {
                    return [
                        { header: 'Permission', accessor: 'name', className: 'font-mono text-xs' },
                        { header: 'Status', accessor: 'status', className: 'w-32' },
                        { header: 'Description', accessor: 'description', className: 'text-xs text-slate-500' },
                    ];
                }
                return [
                    { header: 'Finding', accessor: 'title', className: 'font-medium' },
                    { header: 'Severity', accessor: 'severity', className: 'w-32' },
                    { header: 'File/Component', accessor: 'component', className: 'text-xs font-mono' },
                ];
            default:
                // Auto-generate columns from first item keys if not defined
                return Object.keys(data[0] || {}).slice(0, 5).map(key => ({
                    header: key.charAt(0).toUpperCase() + key.slice(1),
                    accessor: key,
                    className: 'text-sm'
                }));
        }
    }, [tool, data, type]);

    if (!data || data.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-16 text-center bg-gradient-to-b from-white to-slate-50 dark:from-slate-900 dark:to-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="relative mb-6 group">
                    <div className="absolute inset-0 bg-emerald-500/20 dark:bg-emerald-500/10 rounded-full blur-xl group-hover:blur-2xl transition-all duration-500"></div>
                    <div className="relative size-20 rounded-full bg-white dark:bg-slate-800 border-4 border-emerald-50 dark:border-emerald-500/10 shadow-sm flex items-center justify-center">
                        <span className="material-symbols-outlined text-emerald-500 text-4xl transform group-hover:scale-110 transition-transform duration-300">verified_user</span>
                    </div>
                    <div className="absolute -bottom-1 -right-1 bg-emerald-500 text-white p-1.5 rounded-full border-4 border-white dark:border-slate-800 flex items-center justify-center shadow-sm">
                        <span className="material-symbols-outlined text-sm font-bold">check</span>
                    </div>
                </div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Excellent! No Findings Detected</h3>
                <p className="text-slate-500 dark:text-slate-400 max-w-sm mx-auto leading-relaxed">
                    The scan completed successfully and found no security issues or vulnerabilities for this tool.
                </p>
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
            let color = 'text-slate-600';
            const v = String(value).toLowerCase();
            if (v === 'critical' || v === 'high') color = 'text-red-600 font-bold';
            else if (v === 'medium') color = 'text-amber-600 font-bold';
            else if (v === 'low') color = 'text-blue-600';

            return <span className={color}>{value}</span>;
        }

        return value;
    };

    return (
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
                    {data.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
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
    );
}
