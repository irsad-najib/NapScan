"use client";

import React, { useState } from "react";
import { useSchedule } from "@/context/ScheduleContext";

import cronstrue from "cronstrue";

export default function ScheduleList() {
    const { schedules, isLoading, deleteSchedule, pauseSchedule, resumeSchedule } = useSchedule();
    const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
    const [actionLoading, setActionLoading] = useState<string | null>(null);

    // Group schedules by Name + Target + Cron
    // This handles cases where tools might be split across multiple schedule records
    // or combined in one record with comma-separated tools.
    const groupedSchedules = React.useMemo(() => {
        const groups: Record<string, {
            ids: string[];
            schedule: typeof schedules[0];
            tools: Set<string>;
        }> = {};

        schedules.forEach(s => {
            const key = `${s.name}-${s.target}-${s.cron_expression}`;
            if (!groups[key]) {
                groups[key] = {
                    ids: [s.id],
                    schedule: s, // Keep the first one as representative for shared fields
                    tools: new Set<string>()
                };
            } else {
                groups[key].ids.push(s.id);
            }

            // Add tools from this schedule record
            s.tool.split(",").forEach(t => {
                const trimmed = t.trim();
                if (trimmed) groups[key].tools.add(trimmed);
            });
        });

        return Object.values(groups).map(g => ({
            ...g.schedule,
            id: g.ids[0], // Use first ID as primary key for React list
            allIds: g.ids, // Keep track of all IDs in this group
            combinedTools: Array.from(g.tools)
        }));
    }, [schedules]);

    const handleAction = async (ids: string[], actionName: 'pause' | 'resume' | 'delete') => {
        // Use the first ID for loading state
        const primaryId = ids[0];
        setActionLoading(primaryId);
        try {
            if (actionName === 'delete') {
                if (!confirm(`Are you sure you want to delete this schedule?`)) {
                    setActionLoading(null);
                    return;
                }
                await Promise.all(ids.map(id => deleteSchedule(id)));
            } else if (actionName === 'pause') {
                await Promise.all(ids.map(id => pauseSchedule(id)));
            } else if (actionName === 'resume') {
                await Promise.all(ids.map(id => resumeSchedule(id)));
            }
        } catch (error) {
            console.error(`Failed to ${actionName} schedules`, error);
        } finally {
            setActionLoading(null);
        }
    };

    const toggleExpand = (id: string) => {
        setExpandedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) {
                next.delete(id);
            } else {
                next.add(id);
            }
            return next;
        });
    };

    if (isLoading) {
        return (
            <div className="flex justify-center items-center py-12">
                <span className="material-symbols-outlined text-4xl text-slate-400 animate-spin">
                    progress_activity
                </span>
            </div>
        );
    }

    if (groupedSchedules.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm">
                <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-full mb-4">
                    <span className="material-symbols-outlined text-4xl text-slate-400 dark:text-slate-500">
                        event_busy
                    </span>
                </div>
                <p className="text-lg font-bold text-slate-900 dark:text-white">No scheduled scans found</p>
                <p className="text-sm max-w-sm text-center mt-2">Create a new schedule to automate your security scans and stay ahead of threats.</p>
            </div>
        );
    }

    const formatCronDisplay = (expression: string) => {
        try {
            const cleanExpression = expression.replace(/CRON_TZ=[^ ]+ /, "").trim();
            let str = cronstrue.toString(cleanExpression, { use24HourTimeFormat: true });
            str = str.replace(", on day", " ")
                .replace(" of the month", "")
                .replace(", only in", " ")
                .replace(", only on", " ");
            return str;
        } catch (e) {
            return expression;
        }
    };

    return (
        <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-slate-100 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 w-10"></th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Name</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Target</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Tools</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Frequency</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Status</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                        {groupedSchedules.map((schedule) => {
                            const isExpanded = expandedIds.has(schedule.id);
                            const tools = schedule.combinedTools;

                            return (
                                <React.Fragment key={schedule.id}>
                                    <tr
                                        className={`group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150 cursor-pointer ${isExpanded ? "bg-slate-50 dark:bg-slate-700/30" : ""}`}
                                        onClick={() => toggleExpand(schedule.id)}
                                    >
                                        <td className="px-6 py-4">
                                            <span className={`material-symbols-outlined text-slate-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`}>
                                                chevron_right
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-bold text-slate-900 dark:text-white">{schedule.name}</td>
                                        <td className="px-6 py-4 font-mono text-xs text-slate-600 dark:text-slate-300">
                                            {schedule.target}
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex flex-wrap gap-1.5 max-w-[200px]">
                                                {tools.map((tool, idx) => (
                                                    <span key={idx} className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-600 uppercase">
                                                        {tool}
                                                    </span>
                                                ))}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-slate-600 dark:text-slate-400">
                                            <div className="flex flex-col">
                                                <span className="font-medium text-xs text-wrap">{formatCronDisplay(schedule.cron_expression)}</span>
                                                <span className="text-[10px] text-slate-400 font-mono">{schedule.cron_expression}</span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span
                                                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${schedule.is_active
                                                    ? "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30"
                                                    : "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-500/30"
                                                    }`}
                                            >
                                                <span className={`w-1.5 h-1.5 rounded-full ${schedule.is_active ? "bg-emerald-500" : "bg-amber-500"}`}></span>
                                                {schedule.is_active ? "Active" : "Paused"}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <div className="flex items-center justify-end gap-2" onClick={e => e.stopPropagation()}>
                                                {actionLoading === schedule.id ? (
                                                    <span className="material-symbols-outlined text-slate-400 text-sm animate-spin">
                                                        progress_activity
                                                    </span>
                                                ) : (
                                                    <>
                                                        {schedule.is_active ? (
                                                            <button
                                                                onClick={() => handleAction(schedule.allIds, 'pause')}
                                                                className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-all"
                                                                title="Pause"
                                                            >
                                                                <span className="material-symbols-outlined text-[20px]">pause_circle</span>
                                                            </button>
                                                        ) : (
                                                            <button
                                                                onClick={() => handleAction(schedule.allIds, 'resume')}
                                                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 rounded-lg transition-all"
                                                                title="Resume"
                                                            >
                                                                <span className="material-symbols-outlined text-[20px]">play_circle</span>
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => handleAction(schedule.allIds, 'delete')}
                                                            className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all"
                                                            title="Delete"
                                                        >
                                                            <span className="material-symbols-outlined text-[20px]">delete</span>
                                                        </button>
                                                    </>
                                                )}
                                            </div>
                                        </td>
                                    </tr>

                                    {isExpanded && (
                                        <tr className="bg-slate-50 dark:bg-slate-800/20 border-b border-slate-100 dark:border-slate-800">
                                            <td colSpan={7} className="p-0">
                                                <div className="px-6 py-4 ml-10 border-l-2 border-slate-200 dark:border-slate-700 animate-slide-in-top">
                                                    <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-3 px-4">Tools in this schedule</p>
                                                    <div className="flex flex-col gap-3">
                                                        {tools.map((tool, idx) => (
                                                            <div key={idx} className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl p-3">
                                                                <div className="flex items-center gap-3">
                                                                    <div className="size-8 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center font-bold text-xs uppercase tracking-tight text-slate-700 dark:text-slate-300 flex-shrink-0">
                                                                        {tool.substring(0, 2)}
                                                                    </div>
                                                                    <div className="flex-1 min-w-0">
                                                                        <span className="font-bold text-slate-900 dark:text-white text-sm uppercase">
                                                                            {tool}
                                                                        </span>
                                                                        <p className="text-[10px] text-slate-400">
                                                                            Target: <span className="font-mono">{schedule.target}</span>
                                                                        </p>
                                                                    </div>
                                                                    {/* Last run status badge */}
                                                                    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${schedule.last_run_status === 'success' ? "text-emerald-600 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30" :
                                                                        schedule.last_run_status === 'failed' ? "text-red-600 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30" :
                                                                            schedule.last_run_status === 'running' ? "text-blue-600 bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30" :
                                                                                "text-slate-500 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/30"
                                                                        }`}>
                                                                        <span className={`material-symbols-outlined text-sm ${schedule.last_run_status === 'running' ? 'animate-spin' : ''}`}>
                                                                            {schedule.last_run_status === 'success' ? "check_circle" :
                                                                                schedule.last_run_status === 'failed' ? "error" :
                                                                                    schedule.last_run_status === 'running' ? "sync" : "pending"}
                                                                        </span>
                                                                        <span className="capitalize text-[10px]">
                                                                            {schedule.last_run_status || 'Pending'}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
