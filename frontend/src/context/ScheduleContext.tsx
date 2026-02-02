"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { schedulerApi, Schedule, CreateScheduleRequest } from "@/services/api";

interface ScheduleContextType {
    schedules: Schedule[];
    isLoading: boolean;
    error: string | null;
    refreshSchedules: () => Promise<void>;
    createSchedule: (data: CreateScheduleRequest) => Promise<boolean>;
    deleteSchedule: (id: string) => Promise<boolean>;
    pauseSchedule: (id: string) => Promise<boolean>;
    resumeSchedule: (id: string) => Promise<boolean>;
}

const ScheduleContext = createContext<ScheduleContextType | undefined>(undefined);

export function ScheduleProvider({ children }: { children: React.ReactNode }) {
    const [schedules, setSchedules] = useState<Schedule[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchSchedules = useCallback(async () => {
        setIsLoading(true);
        setError(null);
        try {
            const response = await schedulerApi.list();
            if (response.ok && response.data && response.data.data) {
                setSchedules(response.data.data);
            } else {
                setSchedules([]);
                if (!response.ok) {
                    setError((response as any).message || "Failed to fetch schedules");
                }
            }
        } catch (err: any) {
            setError(err.message || "An unexpected error occurred");
            setSchedules([]);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchSchedules();
    }, [fetchSchedules]);

    const createSchedule = async (data: CreateScheduleRequest): Promise<boolean> => {
        try {
            const response = await schedulerApi.create(data);
            if (response.ok) {
                await fetchSchedules();
                return true;
            }
            throw new Error((response as any).message || "Failed to create schedule");
        } catch (err: any) {
            setError(err.message);
            return false;
        }
    };

    const deleteSchedule = async (id: string): Promise<boolean> => {
        try {
            const response = await schedulerApi.delete(id);
            if (response.ok) {
                // Optimistic update
                setSchedules(prev => prev.filter(s => s.id !== id));
                return true;
            }
            throw new Error((response as any).message || "Failed to delete schedule");
        } catch (err: any) {
            setError(err.message);
            // Revert optimistic update by refetching if needed, but for delete it's usually safe
            await fetchSchedules();
            return false;
        }
    };

    const pauseSchedule = async (id: string): Promise<boolean> => {
        try {
            const response = await schedulerApi.pause(id);
            if (response.ok) {
                await fetchSchedules(); // Refetch to get updated status
                return true;
            }
            throw new Error((response as any).message || "Failed to pause schedule");
        } catch (err: any) {
            setError(err.message);
            return false;
        }
    };

    const resumeSchedule = async (id: string): Promise<boolean> => {
        try {
            const response = await schedulerApi.resume(id);
            if (response.ok) {
                await fetchSchedules(); // Refetch to get updated status
                return true;
            }
            throw new Error((response as any).message || "Failed to resume schedule");
        } catch (err: any) {
            setError(err.message);
            return false;
        }
    };

    return (
        <ScheduleContext.Provider
            value={{
                schedules,
                isLoading,
                error,
                refreshSchedules: fetchSchedules,
                createSchedule,
                deleteSchedule,
                pauseSchedule,
                resumeSchedule,
            }}
        >
            {children}
        </ScheduleContext.Provider>
    );
}

export function useSchedule() {
    const context = useContext(ScheduleContext);
    if (context === undefined) {
        throw new Error("useSchedule must be used within a ScheduleProvider");
    }
    return context;
}
