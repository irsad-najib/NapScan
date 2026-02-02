"use client";

import React, { useState } from "react";
import { CreateScheduleRequest } from "@/services/api";
import { useSchedule } from "@/context/ScheduleContext";
import cronstrue from "cronstrue";

interface CreateScheduleDialogProps {
    isOpen: boolean;
    onClose: () => void;
}

const FREQUENCY_PRESETS = [
    { label: "Daily (Midnight)", value: "0 0 * * *" },
    { label: "Weekly (Monday)", value: "0 0 * * 1" },
    { label: "Monthly (1st day)", value: "0 0 1 * *" },
    { label: "Custom Cron", value: "custom" },
];

const SCAN_TOOLS = [
    { label: "Nmap Network Scanner", value: "nmap" },
    { label: "OWASP ZAP", value: "zap" },
    { label: "Nuclei Vulnerability Scanner", value: "nuclei" },
    { label: "SSLyze", value: "sslyze" },
    { label: "FFUF Web Fuzzer", value: "ffuf" },
    { label: "MobSF (Android/iOS)", value: "mobsf" },
];

export default function CreateScheduleDialog({ isOpen, onClose }: CreateScheduleDialogProps) {
    const { createSchedule } = useSchedule();
    const [formData, setFormData] = useState<CreateScheduleRequest>({
        name: "",
        target: "",
        tool: "nmap",
        cron_expression: "0 0 * * *",
    });
    const [frequencyMode, setFrequencyMode] = useState("0 0 * * *");
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    if (!isOpen) return null;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        setError(null);

        const success = await createSchedule(formData);
        if (success) {
            onClose();
            // Reset form
            setFormData({
                name: "",
                target: "",
                tool: "nmap",
                cron_expression: "0 0 * * *",
            });
            setFrequencyMode("0 0 * * *");
        } else {
            setError("Failed to create schedule. Please try again.");
        }
        setIsSubmitting(false);
    };

    const handleFrequencyChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
        const value = e.target.value;
        setFrequencyMode(value);
        if (value !== "custom") {
            setFormData({ ...formData, cron_expression: value });
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
            <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl w-full max-w-md overflow-hidden border border-slate-200 dark:border-slate-800">
                <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                        Schedule New Scan
                    </h2>
                    <button
                        onClick={onClose}
                        className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
                    >
                        <span className="material-symbols-outlined">close</span>
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="p-6 flex flex-col gap-4">
                    {error && (
                        <div className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 p-3 rounded-lg text-sm">
                            {error}
                        </div>
                    )}

                    {/* Schedule Name */}
                    <div className="flex flex-col gap-1">
                        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Schedule Name
                        </label>
                        <input
                            type="text"
                            required
                            className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                            placeholder="e.g., Weekly Network Scan"
                            value={formData.name}
                            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        />
                    </div>

                    {/* Target */}
                    <div className="flex flex-col gap-1">
                        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Target URL/IP
                        </label>
                        <input
                            type="text"
                            required
                            className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                            placeholder="e.g., example.com"
                            value={formData.target}
                            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                        />
                    </div>

                    {/* Tool Selection */}
                    <div className="flex flex-col gap-1">
                        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Select Tool
                        </label>
                        <select
                            className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                            value={formData.tool}
                            onChange={(e) => setFormData({ ...formData, tool: e.target.value })}
                        >
                            {SCAN_TOOLS.map((tool) => (
                                <option key={tool.value} value={tool.value}>
                                    {tool.label}
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Frequency */}
                    <div className="flex flex-col gap-1">
                        <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                            Frequency
                        </label>
                        <select
                            className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                            value={frequencyMode}
                            onChange={handleFrequencyChange}
                        >
                            {FREQUENCY_PRESETS.map((preset) => (
                                <option key={preset.value} value={preset.value}>
                                    {preset.label}
                                </option>
                            ))}
                        </select>
                    </div>

                    {/* Custom Cron Input */}
                    {frequencyMode === "custom" && (
                        <div className="flex flex-col gap-1">
                            <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                                Cron Expression
                            </label>
                            <input
                                type="text"
                                required
                                className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none font-mono text-sm"
                                placeholder="* * * * *"
                                value={formData.cron_expression}
                                onChange={(e) => setFormData({ ...formData, cron_expression: e.target.value })}
                            />
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                                Format: Minute Hour Day Month DayOfWeek
                            </p>
                            {formData.cron_expression && (
                                <p className="text-xs text-blue-600 dark:text-blue-400 font-medium">
                                    Preview: {(() => {
                                        try {
                                            return cronstrue.toString(formData.cron_expression);
                                        } catch (e) {
                                            return "Invalid Cron Expression";
                                        }
                                    })()}
                                </p>
                            )}
                        </div>
                    )}

                    {/* Submit Actions */}
                    <div className="flex justify-end gap-3 mt-4">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                            disabled={isSubmitting}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-lg shadow-blue-500/20 transition-all flex items-center gap-2"
                            disabled={isSubmitting}
                        >
                            {isSubmitting ? (
                                <>
                                    <span className="material-symbols-outlined text-sm animate-spin">
                                        progress_activity
                                    </span>
                                    Saving...
                                </>
                            ) : (
                                "Create Schedule"
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
