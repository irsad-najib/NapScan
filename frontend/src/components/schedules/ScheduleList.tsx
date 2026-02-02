"use client";

import React, { useState } from "react";
import { useSchedule } from "@/context/ScheduleContext";
import { Schedule } from "@/services/api";

import cronstrue from "cronstrue";

export default function ScheduleList() {
    const { schedules, isLoading, deleteSchedule, pauseSchedule, resumeSchedule } = useSchedule();
    const [actionLoading, setActionLoading] = useState<string | null>(null);

    const handleAction = async (id: string, action: () => Promise<boolean>) => {
        setActionLoading(id);
        await action();
        setActionLoading(null);
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

    if (schedules.length === 0) {
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

    return (
        <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden backdrop-blur-sm">
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-slate-100 dark:bg-slate-700/30 border-b border-slate-200 dark:border-slate-700">
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Name</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Target</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Tool</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Frequency</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Status</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400">Next Run</th>
                            <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-400 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                        {schedules.map((schedule) => (
                            <tr
                                key={schedule.id}
                                className="text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors"
                            >
                                <td className="px-6 py-4 font-bold text-slate-900 dark:text-white">{schedule.name}</td>
                                <td className="px-6 py-4 font-mono text-xs">{schedule.target}</td>
                                <td className="px-6 py-4">
                                    <span className="inline-flex items-center px-2.5 py-1 rounded-lg bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs font-bold uppercase border border-blue-100 dark:border-blue-800/50">
                                        {schedule.tool}
                                    </span>
                                </td>
                                <td className="px-6 py-4 text-slate-600 dark:text-slate-400 pl-8">
                                    <div className="flex flex-col">
                                        <span className="font-medium">{cronstrue.toString(schedule.cron_expression)}</span>
                                        <div className="flex items-center gap-2 mt-0.5">
                                            <span className="text-xs text-slate-400 font-mono">{schedule.cron_expression}</span>
                                            {schedule.last_run_status && (
                                                <span
                                                    className={`w-2 h-2 rounded-full ${schedule.last_run_status === 'running' ? 'bg-blue-500 animate-pulse' :
                                                            schedule.last_run_status === 'success' ? 'bg-green-500' :
                                                                'bg-red-500'
                                                        }`}
                                                    title={`Last Run: ${schedule.last_run_status}`}
                                                />
                                            )}
                                        </div>
                                        {schedule.last_run && (
                                            <span className="text-[10px] text-slate-400">
                                                Last: {new Date(schedule.last_run).toLocaleString()}
                                            </span>
                                        )}
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
                                <td className="px-6 py-4 text-slate-500 dark:text-slate-400 font-medium">
                                    {schedule.next_run ? new Date(schedule.next_run).toLocaleString() : "-"}
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <div className="flex items-center justify-end gap-2">
                                        {actionLoading === schedule.id ? (
                                            <span className="material-symbols-outlined text-slate-400 text-sm animate-spin">
                                                progress_activity
                                            </span>
                                        ) : (
                                            <>
                                                {schedule.is_active ? (
                                                    <button
                                                        onClick={() => handleAction(schedule.id, () => pauseSchedule(schedule.id))}
                                                        className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-all"
                                                        title="Pause Schedule"
                                                    >
                                                        <span className="material-symbols-outlined text-[20px]">pause_circle</span>
                                                    </button>
                                                ) : (
                                                    <button
                                                        onClick={() => handleAction(schedule.id, () => resumeSchedule(schedule.id))}
                                                        className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 rounded-lg transition-all"
                                                        title="Resume Schedule"
                                                    >
                                                        <span className="material-symbols-outlined text-[20px]">play_circle</span>
                                                    </button>
                                                )}
                                                <button
                                                    onClick={() => {
                                                        if (confirm("Are you sure you want to delete this schedule?")) {
                                                            handleAction(schedule.id, () => deleteSchedule(schedule.id));
                                                        }
                                                    }}
                                                    className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all"
                                                    title="Delete Schedule"
                                                >
                                                    <span className="material-symbols-outlined text-[20px]">delete</span>
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
        </div>
    );
}
