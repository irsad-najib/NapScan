"use client";

import React, { useState } from "react";
import { useSchedule } from "@/context/ScheduleContext";
import { Schedule } from "@/services/api";

import cronstrue from "cronstrue";

export default function ScheduleList() {
    const { schedules, isLoading, deleteSchedule, pauseSchedule, resumeSchedule } = useSchedule();
    const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
    const [actionLoading, setActionLoading] = useState<string | null>(null);

    // Group schedules by Name + Target + Cron (Logic: same "intent")
    // Or just Name if the user strictly wants Name.
    // User said: "name testingnya sama itu jadi satu" -> "same testing name become one"
    const groupedSchedules = React.useMemo(() => {
        const groups: Record<string, Schedule[]> = {};
        schedules.forEach(s => {
            // Key by name. If names are empty, fallback to ID (shouldn't happen with proper form)
            const key = s.name || s.id;
            if (!groups[key]) {
                groups[key] = [];
            }
            groups[key].push(s);
        });
        return groups;
    }, [schedules]);

    const handleGroupAction = async (groupName: string, actionName: 'pause' | 'resume' | 'delete') => {
        const groupItems = groupedSchedules[groupName];
        if (!groupItems) return;

        // For feedback, maybe set loading state
        setActionLoading(groupName);

        try {
            if (actionName === 'delete') {
                if (!confirm(`Are you sure you want to delete all ${groupItems.length} schedules in "${groupName}"?`)) {
                    setActionLoading(null);
                    return;
                }
                await Promise.all(groupItems.map(s => deleteSchedule(s.id)));
            } else if (actionName === 'pause') {
                await Promise.all(groupItems.map(s => pauseSchedule(s.id)));
            } else if (actionName === 'resume') {
                await Promise.all(groupItems.map(s => resumeSchedule(s.id)));
            }
        } catch (error) {
            console.error(`Failed to ${actionName} group ${groupName}`, error);
        } finally {
            setActionLoading(null);
        }
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

    const groupKeys = Object.keys(groupedSchedules);

    if (groupKeys.length === 0) {
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
            let str = cronstrue.toString(expression, { use24HourTimeFormat: true });
            // Simplify text
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
                        {groupKeys.map((groupName) => {
                            const items = groupedSchedules[groupName];
                            // Representative item (first one) for shared props like Target/Cron
                            // Assumption: Grouped items share Target/Frequency usually, or we show "Mixed"
                            const first = items[0];
                            const isExpanded = expandedGroup === groupName;

                            // Derived status: active if ANY is active? or ALL? 
                            // Usually "Active" if at least one is active.
                            const hasActive = items.some(i => i.is_active);
                            const allPaused = items.every(i => !i.is_active);

                            // Tools list chips source
                            const tools = items.map(i => i.tool);

                            return (
                                <React.Fragment key={groupName}>
                                    <tr
                                        className={`group hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors duration-150 cursor-pointer ${isExpanded ? "bg-slate-50 dark:bg-slate-700/30" : ""}`}
                                        onClick={() => setExpandedGroup(isExpanded ? null : groupName)}
                                    >
                                        <td className="px-6 py-4">
                                            <span className={`material-symbols-outlined text-slate-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`}>
                                                chevron_right
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-bold text-slate-900 dark:text-white">{groupName}</td>
                                        <td className="px-6 py-4 font-mono text-xs text-slate-600 dark:text-slate-300">
                                            {first.target}
                                            {items.some(i => i.target !== first.target) && <span className="text-xs text-slate-400 ml-1">(multiple)</span>}
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex flex-wrap gap-1">
                                                {tools.slice(0, 3).map((tool, idx) => (
                                                    <span key={idx} className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-600 uppercase">
                                                        {tool}
                                                    </span>
                                                ))}
                                                {tools.length > 3 && (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-700 text-slate-500 border border-slate-200 dark:border-slate-600">
                                                        +{tools.length - 3}
                                                    </span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-slate-600 dark:text-slate-400">
                                            <div className="flex flex-col">
                                                <span className="font-medium text-xs text-wrap">{formatCronDisplay(first.cron_expression)}</span>
                                                <span className="text-[10px] text-slate-400 font-mono">{first.cron_expression}</span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span
                                                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold ${!allPaused
                                                    ? "bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30"
                                                    : "bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-500/30"
                                                    }`}
                                            >
                                                <span className={`w-1.5 h-1.5 rounded-full ${!allPaused ? "bg-emerald-500" : "bg-amber-500"}`}></span>
                                                {!allPaused ? "Active" : "Paused"}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <div className="flex items-center justify-end gap-2" onClick={e => e.stopPropagation()}>
                                                {actionLoading === groupName ? (
                                                    <span className="material-symbols-outlined text-slate-400 text-sm animate-spin">
                                                        progress_activity
                                                    </span>
                                                ) : (
                                                    <>
                                                        {!allPaused ? (
                                                            <button
                                                                onClick={() => handleGroupAction(groupName, 'pause')}
                                                                className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-all"
                                                                title="Pause All"
                                                            >
                                                                <span className="material-symbols-outlined text-[20px]">pause_circle</span>
                                                            </button>
                                                        ) : (
                                                            <button
                                                                onClick={() => handleGroupAction(groupName, 'resume')}
                                                                className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 rounded-lg transition-all"
                                                                title="Resume All"
                                                            >
                                                                <span className="material-symbols-outlined text-[20px]">play_circle</span>
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => handleGroupAction(groupName, 'delete')}
                                                            className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all"
                                                            title="Delete Group"
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
                                                    <div className="hidden md:flex items-center px-4 mb-3 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                                                        <div className="w-48">Schedule Component</div>
                                                        <div className="flex-1 px-4">Target</div>
                                                        <div className="w-32">Frequency</div>
                                                        <div className="w-32">Last Status</div>
                                                        <div className="w-24 text-right px-4">Status</div>
                                                    </div>

                                                    <div className="flex flex-col gap-3">
                                                        {items.map(schedule => (
                                                            <div key={schedule.id} className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden transition-all duration-200 hover:shadow-md flex items-center p-3">
                                                                {/* Tool Name */}
                                                                <div className="w-48 flex items-center gap-3">
                                                                    <div className="size-8 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center font-bold text-xs uppercase tracking-tight text-slate-700 dark:text-slate-300">
                                                                        {schedule.tool.substring(0, 2)}
                                                                    </div>
                                                                    <div className="flex flex-col">
                                                                        <span className="font-bold text-slate-900 dark:text-white text-sm uppercase">
                                                                            {schedule.tool}
                                                                        </span>
                                                                    </div>
                                                                </div>

                                                                {/* Target */}
                                                                <div className="flex-1 px-4">
                                                                    <span className="text-sm font-mono text-slate-600 dark:text-slate-400">
                                                                        {schedule.target}
                                                                    </span>
                                                                    <p className="text-[10px] text-slate-400">Target</p>
                                                                </div>

                                                                {/* Frequency */}
                                                                <div className="w-32 flex flex-col justify-center">
                                                                    <span className="text-xs font-medium text-slate-600 dark:text-slate-400 break-words" title={formatCronDisplay(schedule.cron_expression)}>
                                                                        {formatCronDisplay(schedule.cron_expression)}
                                                                    </span>
                                                                    <span className="text-[10px] text-slate-400 font-mono break-all">{schedule.cron_expression}</span>
                                                                </div>

                                                                {/* Last Status */}
                                                                <div className="w-32 flex items-center gap-2">
                                                                    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wide border ${schedule.last_run_status === 'success' ? "text-emerald-600 bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/30" :
                                                                        schedule.last_run_status === 'failed' ? "text-red-600 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30" :
                                                                            schedule.last_run_status === 'running' ? "text-blue-600 bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30" :
                                                                                "text-slate-500 bg-slate-50 dark:bg-slate-500/10 border-slate-200 dark:border-slate-500/30"
                                                                        }`}>
                                                                        {schedule.last_resource_id ? (
                                                                            <a
                                                                                href={`/scans/${schedule.last_resource_id}`}
                                                                                className="flex items-center gap-1.5 hover:underline"
                                                                                title="View Scan Result"
                                                                            >
                                                                                <span className={`material-symbols-outlined text-sm ${schedule.last_run_status === 'running' ? 'animate-spin' : ''}`}>
                                                                                    {schedule.last_run_status === 'success' ? "check_circle" :
                                                                                        schedule.last_run_status === 'failed' ? "error" :
                                                                                            schedule.last_run_status === 'running' ? "sync" : "pending"}
                                                                                </span>
                                                                                <span className="capitalize text-[10px]">
                                                                                    {schedule.last_run_status || 'Never Ran'}
                                                                                </span>
                                                                                <span className="material-symbols-outlined text-[10px]">open_in_new</span>
                                                                            </a>
                                                                        ) : (
                                                                            <>
                                                                                <span className={`material-symbols-outlined text-sm ${schedule.last_run_status === 'running' ? 'animate-spin' : ''}`}>
                                                                                    {schedule.last_run_status === 'success' ? "check_circle" :
                                                                                        schedule.last_run_status === 'failed' ? "error" :
                                                                                            schedule.last_run_status === 'running' ? "sync" : "pending"}
                                                                                </span>
                                                                                <span className="capitalize text-[10px]">
                                                                                    {schedule.last_run_status || 'Never Ran'}
                                                                                </span>
                                                                            </>
                                                                        )}
                                                                    </div>
                                                                </div>

                                                                {/* Individual Status */}
                                                                <div className="w-24 text-right px-4">
                                                                    {schedule.is_active ? (
                                                                        <span className="text-xs text-emerald-600 font-bold">Active</span>
                                                                    ) : (
                                                                        <span className="text-xs text-amber-600 font-bold">Paused</span>
                                                                    )}
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
