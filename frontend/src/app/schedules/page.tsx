"use client";

import React, { useState } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import ScheduleList from "@/components/schedules/ScheduleList";
import CreateScheduleDialog from "@/components/schedules/CreateScheduleDialog";
import { AuthRequiredDialog } from "@/components/common/AuthRequiredDialog";
import { useSchedule } from "@/context/ScheduleContext";
import { useAuth } from "@/context/AuthContext";

export default function SchedulesPage() {
    const { refreshSchedules } = useSchedule();
    const { isAuthenticated } = useAuth();
    const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [showAuthDialog, setShowAuthDialog] = useState(false);
    const [searchQuery, setSearchQuery] = useState("");

    const handleRefresh = async () => {
        setIsRefreshing(true);
        await refreshSchedules();
        setIsRefreshing(false);
    };

    const handleCreateClick = () => {
        if (!isAuthenticated) {
            setShowAuthDialog(true);
            return;
        }
        setIsCreateDialogOpen(true);
    };

    return (
        <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
            <Sidebar />
            <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
                <Header
                    title="Scheduled Scans"
                    searchPlaceholder="Search schedules..."
                    searchValue={searchQuery}
                    onSearch={setSearchQuery}
                />

                <main className="flex-1 overflow-y-auto overflow-x-hidden px-8 py-10 md:px-12 md:py-12 scroll-smooth">
                    <div className="max-w-7xl mx-auto flex flex-col gap-8 pb-20">
                        {/* Actions Bar */}
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                            <div className="flex flex-col gap-2">
                                <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                                    Active Schedules
                                </h2>
                                <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                                    Manage your automated security scans
                                </p>
                            </div>

                            <div className="flex items-center gap-3">
                                <button
                                    onClick={handleRefresh}
                                    className={`p-3.5 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-colors border border-slate-200 dark:border-slate-800 ${isRefreshing ? "animate-spin" : ""
                                        }`}
                                    title="Refresh List"
                                >
                                    <span className="material-symbols-outlined">refresh</span>
                                </button>
                                <button
                                    onClick={handleCreateClick}
                                    className="flex items-center justify-center gap-2.5 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3.5 px-6 rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95 shrink-0 h-12 whitespace-nowrap"
                                >
                                    <span className="material-symbols-outlined text-lg">add</span>
                                    <span>New Schedule</span>
                                </button>
                            </div>
                        </div>

                        {/* List Component */}
                        <ScheduleList searchQuery={searchQuery} />
                    </div>
                </main>
            </div>

            {/* Dialogs */}
            <CreateScheduleDialog
                isOpen={isCreateDialogOpen}
                onClose={() => setIsCreateDialogOpen(false)}
            />

            <AuthRequiredDialog
                isOpen={showAuthDialog}
                onClose={() => setShowAuthDialog(false)}
            />
        </div>
    );
}
