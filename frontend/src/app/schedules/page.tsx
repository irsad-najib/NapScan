"use client";

import React, { useState } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import ScheduleList from "@/components/schedules/ScheduleList";
import CreateScheduleDialog from "@/components/schedules/CreateScheduleDialog";
import { useSchedule } from "@/context/ScheduleContext";

export default function SchedulesPage() {
    const { refreshSchedules } = useSchedule();
    const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const handleRefresh = async () => {
        setIsRefreshing(true);
        await refreshSchedules();
        setIsRefreshing(false);
    };

    return (
        <div className="flex bg-background-light dark:bg-background-dark min-h-screen">
            <Sidebar />
            <div className="flex-1 flex flex-col h-screen overflow-hidden">
                <Header title="Scheduled Scans" />

                <main className="flex-1 overflow-y-auto p-6 md:p-8">
                    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
                        {/* Actions Bar */}
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                                    Active Schedules
                                </h2>
                                <p className="text-sm text-slate-500 dark:text-slate-400">
                                    Manage your automated security scans
                                </p>
                            </div>

                            <div className="flex items-center gap-3">
                                <button
                                    onClick={handleRefresh}
                                    className={`p-2.5 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors border border-slate-200 dark:border-slate-800 ${isRefreshing ? "animate-spin" : ""
                                        }`}
                                    title="Refresh List"
                                >
                                    <span className="material-symbols-outlined">refresh</span>
                                </button>
                                <button
                                    onClick={() => setIsCreateDialogOpen(true)}
                                    className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/20 transition-all flex items-center gap-2"
                                >
                                    <span className="material-symbols-outlined text-lg">add</span>
                                    New Schedule
                                </button>
                            </div>
                        </div>

                        {/* List Component */}
                        <ScheduleList />
                    </div>
                </main>
            </div>

            {/* Dialog */}
            <CreateScheduleDialog
                isOpen={isCreateDialogOpen}
                onClose={() => setIsCreateDialogOpen(false)}
            />
        </div>
    );
}
