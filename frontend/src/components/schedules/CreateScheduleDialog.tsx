"use client";

import React, { useState, useMemo } from "react";
import { CreateScheduleRequest, ToolKey, scannersApi } from "@/services/api";
import { useSchedule } from "@/context/ScheduleContext";
import cronstrue from "cronstrue";

interface CreateScheduleDialogProps {
    isOpen: boolean;
    onClose: () => void;
}

const TOOLS_CONFIG = [
    { id: "nmap", label: "Nmap", icon: "router", type: "web" },
    { id: "zap", label: "OWASP ZAP", icon: "bug_report", type: "web" },
    { id: "openvas", label: "OpenVAS", icon: "shield", type: "web" },
    { id: "nuclei", label: "Nuclei", icon: "bolt", type: "web" },
    { id: "sslyze", label: "SSLyze", icon: "lock", type: "web" },
    { id: "ffuf", label: "Ffuf", icon: "search", type: "web" },
    { id: "mobsf", label: "MobSF", icon: "android", type: "mobile" },
];

type FrequencyType = "once" | "every_2h" | "every_6h" | "every_12h" | "daily" | "weekly" | "monthly";

const FREQUENCY_OPTIONS: { value: FrequencyType; label: string; icon: string; description: string }[] = [
    { value: "once", label: "Once", icon: "event", description: "Run only once at the specified time" },
    { value: "every_2h", label: "Every 2 Hours", icon: "timer", description: "Repeat every 2 hours" },
    { value: "every_6h", label: "Every 6 Hours", icon: "schedule", description: "Repeat every 6 hours (4x/day)" },
    { value: "every_12h", label: "Every 12 Hours", icon: "hourglass_top", description: "Repeat every 12 hours (2x/day)" },
    { value: "daily", label: "Daily", icon: "today", description: "Repeat every day at the same time" },
    { value: "weekly", label: "Weekly", icon: "date_range", description: "Repeat every week on the same day" },
    { value: "monthly", label: "Monthly", icon: "calendar_month", description: "Repeat every month on the same date" },
];

export default function CreateScheduleDialog({ isOpen, onClose }: CreateScheduleDialogProps) {
    const { createSchedule } = useSchedule();

    // Form State
    const [scanType, setScanType] = useState<"web" | "mobile">("web");
    const [target, setTarget] = useState("");
    const [apkFile, setApkFile] = useState<File | null>(null);
    const [selectedTools, setSelectedTools] = useState<ToolKey[]>([]);

    // Authorization State
    const [isAuthorized, setIsAuthorized] = useState(false);

    // Schedule Date/Time & Frequency
    const [scheduleDate, setScheduleDate] = useState("");
    const [scheduleTime, setScheduleTime] = useState("");
    const [frequency, setFrequency] = useState<FrequencyType>("once");
    const [isFrequencyOpen, setIsFrequencyOpen] = useState(false);

    const [scanName, setScanName] = useState("");

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const toggleTool = (toolId: ToolKey) => {
        setSelectedTools(prev =>
            prev.includes(toolId)
                ? prev.filter(t => t !== toolId)
                : [...prev, toolId]
        );
    };

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setApkFile(e.target.files[0]);
            setTarget(e.target.files[0].name);
        }
    };

    /** Build the cron expression based on frequency + selected date/time */
    const buildCronExpression = (dateObj: Date, freq: FrequencyType): string => {
        const min = dateObj.getMinutes();
        const hour = dateObj.getHours();
        const dom = dateObj.getDate();
        const month = dateObj.getMonth() + 1;
        const dow = dateObj.getDay(); // 0=Sun, 1=Mon, ...

        const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

        let cronBody: string;

        switch (freq) {
            case "once":
                // Run once: specific min, hour, day of month, month
                cronBody = `${min} ${hour} ${dom} ${month} *`;
                break;
            case "every_2h":
                // Every 2 hours starting from the selected minute
                cronBody = `${min} */2 * * *`;
                break;
            case "every_6h":
                // Every 6 hours starting from the selected minute
                cronBody = `${min} */6 * * *`;
                break;
            case "every_12h":
                // Every 12 hours starting from the selected minute
                cronBody = `${min} */12 * * *`;
                break;
            case "daily":
                // Every day at the same hour:minute
                cronBody = `${min} ${hour} * * *`;
                break;
            case "weekly":
                // Every week on the same day-of-week at the same hour:minute
                cronBody = `${min} ${hour} * * ${dow}`;
                break;
            case "monthly":
                // Every month on the same day-of-month at the same hour:minute
                cronBody = `${min} ${hour} ${dom} * *`;
                break;
            default:
                cronBody = `${min} ${hour} ${dom} ${month} *`;
        }

        return `CRON_TZ=${timeZone} ${cronBody}`;
    };

    /** Live preview of the cron expression */
    const cronPreview = useMemo(() => {
        if (!scheduleDate || !scheduleTime) return null;
        try {
            const dateObj = new Date(`${scheduleDate}T${scheduleTime}`);
            if (isNaN(dateObj.getTime())) return null;
            const full = buildCronExpression(dateObj, frequency);
            // Extract just the cron part (after CRON_TZ=...)
            const cronPart = full.split(" ").slice(1).join(" ");
            return cronstrue.toString(cronPart);
        } catch {
            return null;
        }
    }, [scheduleDate, scheduleTime, frequency]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setIsSubmitting(true);

        try {
            if (selectedTools.length === 0) {
                throw new Error("Please select at least one scanner tool.");
            }

            if (scanType === "web" && !target) {
                throw new Error("Please enter a target URL or Host.");
            }
            if (scanType === "mobile" && !apkFile) {
                throw new Error("Please upload an APK file.");
            }
            if (scanType === "mobile" && !isAuthorized) {
                throw new Error("Please confirm your authorization to scan this application.");
            }

            if (!scheduleDate || !scheduleTime) {
                throw new Error("Please select a date and time for the schedule.");
            }
            // Mobile Upload Logic
            let finalTarget = target;
            if (scanType === "mobile" && apkFile) {
                try {
                    // Upload the APK file first
                    const uploadResult = await scannersApi.mobsf.upload(apkFile);

                    if (!uploadResult.ok) {
                        throw new Error(uploadResult.message || "Failed to upload APK file");
                    }

                    if (!uploadResult.data.success || !uploadResult.data.data) {
                        throw new Error(uploadResult.data.message || "Failed to upload APK file");
                    }

                    // Use the file ID as the target for the schedule
                    finalTarget = uploadResult.data.data.file_id.toString();
                    console.log("APK Uploaded, File ID:", finalTarget);
                } catch (e: any) {
                    throw new Error(`APK Upload failed: ${e.message}`);
                }
            }

            const dateObj = new Date(`${scheduleDate}T${scheduleTime}`);
            if (isNaN(dateObj.getTime())) {
                throw new Error("Invalid Date/Time");
            }

            const cronExpression = buildCronExpression(dateObj, frequency);
            console.log("Generated Cron:", cronExpression);

            const req: CreateScheduleRequest = {
                name: scanName || `Scheduled Scan`,
                target: finalTarget,
                tool: selectedTools.join(","),
                cron_expression: cronExpression,
            };

            await createSchedule(req);

            onClose();
            // Reset
            setTarget("");
            setApkFile(null);
            setSelectedTools([]);
            setScanName("");
            setScheduleDate("");
            setScheduleTime("");
            setFrequency("once");
            setIsAuthorized(false);
        } catch (err: any) {
            setError(err.message || "Failed to create schedule");
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!isOpen) return null;

    const filteredTools = TOOLS_CONFIG.filter(t => t.type === scanType);
    const selectedFreq = FREQUENCY_OPTIONS.find(f => f.value === frequency)!;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4 animate-fade-in">
            <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-3xl overflow-hidden border border-slate-200 dark:border-slate-800 flex flex-col max-h-[90vh]">

                {/* Header */}
                <div className="px-8 py-6 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-white dark:bg-slate-900 sticky top-0 z-10">
                    <h2 className="text-xl font-bold text-slate-900 dark:text-white">
                        Schedule New Scan
                    </h2>
                    <button
                        onClick={onClose}
                        className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
                    >
                        <span className="material-symbols-outlined text-2xl">close</span>
                    </button>
                </div>

                {/* Form Content */}
                <form onSubmit={handleSubmit} className="p-8 overflow-y-auto custom-scrollbar flex flex-col gap-8">
                    {error && (
                        <div className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 p-4 rounded-xl text-sm font-medium flex items-center gap-2">
                            <span className="material-symbols-outlined text-lg">error</span>
                            {error}
                        </div>
                    )}

                    {/* Scan Type */}
                    <div className="flex flex-col gap-3">
                        <label className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-1">
                            Scan Type <span className="text-red-500">*</span>
                        </label>
                        <div className="grid grid-cols-2 gap-4">
                            <button
                                type="button"
                                onClick={() => { setScanType("web"); setApkFile(null); setTarget(""); setSelectedTools([]); setIsAuthorized(false); }}
                                className={`flex flex-col items-center justify-center p-6 rounded-xl border-2 transition-all duration-200 gap-3 ${scanType === "web"
                                    ? "border-blue-500 bg-blue-50/50 dark:bg-blue-900/10 text-blue-700 dark:text-blue-400"
                                    : "border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-600 dark:text-slate-400"
                                    }`}
                            >
                                <span className={`material-symbols-outlined text-3xl ${scanType === "web" ? "text-blue-500" : "text-slate-400"}`}>language</span>
                                <div className="text-center">
                                    <span className="block font-bold">Web Target</span>
                                    <span className="text-xs opacity-70 mt-1">Scan websites, APIs, or servers</span>
                                </div>
                            </button>

                            <button
                                type="button"
                                onClick={() => { setScanType("mobile"); setApkFile(null); setTarget(""); setSelectedTools([]); setIsAuthorized(false); }}
                                className={`flex flex-col items-center justify-center p-6 rounded-xl border-2 transition-all duration-200 gap-3 ${scanType === "mobile"
                                    ? "border-blue-500 bg-blue-50/50 dark:bg-blue-900/10 text-blue-700 dark:text-blue-400"
                                    : "border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-600 dark:text-slate-400"
                                    }`}
                            >
                                <span className={`material-symbols-outlined text-3xl ${scanType === "mobile" ? "text-blue-500" : "text-slate-400"}`}>android</span>
                                <div className="text-center">
                                    <span className="block font-bold">APK Mobile</span>
                                    <span className="text-xs opacity-70 mt-1">Analyze Android applications</span>
                                </div>
                            </button>
                        </div>
                    </div>

                    {/* Target Input (Web URL or APK File) */}
                    <div className="flex flex-col gap-3">
                        <label className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-1">
                            {scanType === "web" ? "Target URL / Host" : "APK File"} <span className="text-red-500">*</span>
                        </label>

                        {scanType === "web" ? (
                            <input
                                type="text"
                                required
                                className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
                                placeholder="Enter URL or IP address (e.g., https://example.com or 192.168.1.1)"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                            />
                        ) : (
                            <div className="relative">
                                <input
                                    type="file"
                                    accept=".apk"
                                    required={scanType === "mobile"}
                                    onChange={handleFileChange}
                                    className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-bold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 transition-all"
                                />
                                {apkFile && (
                                    <div className="absolute right-4 top-1/2 -translate-y-1/2 text-emerald-500 flex items-center gap-1 text-sm font-bold animate-fade-in">
                                        <span className="material-symbols-outlined text-lg">check_circle</span>
                                        Ready
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Authorization Checkbox (Mobile Only) */}
                    {scanType === "mobile" && (
                        <div className="flex items-start gap-3 p-4 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-xl animate-fade-in">
                            <div className="pt-0.5">
                                <input
                                    type="checkbox"
                                    id="authorization-check"
                                    className="w-5 h-5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer"
                                    checked={isAuthorized}
                                    onChange={(e) => setIsAuthorized(e.target.checked)}
                                />
                            </div>
                            <label htmlFor="authorization-check" className="text-sm text-slate-700 dark:text-slate-300 cursor-pointer select-none">
                                <span className="font-bold block mb-1">Authorization Confirmation</span>
                                I confirm that I am authorized to scan this application and that I have the necessary permissions to perform security testing on it.
                            </label>
                        </div>
                    )}

                    {/* Scanner Tools */}
                    <div className="flex flex-col gap-3">
                        <label className="text-sm font-bold text-slate-900 dark:text-slate-300 flex items-center gap-1">
                            Scanner Tools <span className="text-red-500">*</span>
                        </label>
                        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-3 gap-3">
                            {filteredTools.map((tool) => {
                                const isSelected = selectedTools.includes(tool.id as ToolKey);
                                return (
                                    <div
                                        key={tool.id}
                                        onClick={() => toggleTool(tool.id as ToolKey)}
                                        className={`cursor-pointer rounded-xl border p-3 flex items-center gap-3 transition-all duration-200 select-none ${isSelected
                                            ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20 shadow-sm"
                                            : "border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-white dark:bg-slate-800/50"
                                            }`}
                                    >
                                        <div className={`w-5 h-5 rounded-md border flex items-center justify-center transition-colors flex-shrink-0 ${isSelected ? "bg-blue-500 border-blue-500" : "border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700"
                                            }`}>
                                            {isSelected && <span className="material-symbols-outlined text-white text-sm font-bold">check</span>}
                                        </div>
                                        <div className="flex flex-col min-w-0">
                                            <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                                                <span className="material-symbols-outlined text-lg flex-shrink-0">{tool.icon}</span>
                                                <span className="text-sm font-semibold truncate">{tool.label}</span>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Frequency Dropdown */}
                    <div className="flex flex-col gap-3">
                        <label className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-1">
                            Frequency <span className="text-red-500">*</span>
                        </label>
                        <div className="relative">
                            <button
                                type="button"
                                onClick={() => setIsFrequencyOpen(!isFrequencyOpen)}
                                className="w-full flex items-center justify-between px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white hover:border-blue-400 dark:hover:border-blue-500 focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                            >
                                <div className="flex items-center gap-3">
                                    <span className="material-symbols-outlined text-lg text-blue-500">{selectedFreq.icon}</span>
                                    <div className="text-left">
                                        <span className="block font-semibold text-sm">{selectedFreq.label}</span>
                                        <span className="block text-xs text-slate-500 dark:text-slate-400">{selectedFreq.description}</span>
                                    </div>
                                </div>
                                <span className={`material-symbols-outlined text-lg text-slate-400 transition-transform duration-200 ${isFrequencyOpen ? "rotate-180" : ""}`}>
                                    expand_more
                                </span>
                            </button>

                            {/* Dropdown Menu */}
                            {isFrequencyOpen && (
                                <div className="absolute z-20 mt-2 w-full bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-xl overflow-hidden animate-fade-in">
                                    {FREQUENCY_OPTIONS.map((opt) => (
                                        <button
                                            type="button"
                                            key={opt.value}
                                            onClick={() => { setFrequency(opt.value); setIsFrequencyOpen(false); }}
                                            className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors ${frequency === opt.value
                                                ? "bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400"
                                                : "text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700/50"
                                                }`}
                                        >
                                            <span className={`material-symbols-outlined text-lg ${frequency === opt.value ? "text-blue-500" : "text-slate-400"}`}>
                                                {opt.icon}
                                            </span>
                                            <div>
                                                <span className="block font-semibold text-sm">{opt.label}</span>
                                                <span className="block text-xs opacity-70">{opt.description}</span>
                                            </div>
                                            {frequency === opt.value && (
                                                <span className="material-symbols-outlined text-blue-500 ml-auto text-lg">check</span>
                                            )}
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Scheduled Date & Time */}
                    <div className="grid grid-cols-2 gap-4 animate-fade-in">
                        <div>
                            <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2">
                                {frequency === "once" ? "Date" : "Start Date"} <span className="text-red-500">*</span>
                            </label>
                            <div className="relative">
                                <input
                                    type="date"
                                    className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none transition-all cursor-pointer"
                                    value={scheduleDate}
                                    onChange={(e) => setScheduleDate(e.target.value)}
                                    min={new Date().toISOString().split('T')[0]}
                                    onClick={(e) => e.currentTarget.showPicker()}
                                />
                            </div>
                        </div>
                        <div>
                            <label className="block text-sm font-bold text-slate-900 dark:text-white mb-2">
                                Time <span className="text-red-500">*</span>
                            </label>
                            <div className="relative">
                                <input
                                    type="time"
                                    className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none transition-all cursor-pointer"
                                    value={scheduleTime}
                                    onChange={(e) => setScheduleTime(e.target.value)}
                                    onClick={(e) => e.currentTarget.showPicker()}
                                />
                            </div>
                        </div>
                    </div>

                    {/* Cron Preview */}
                    {cronPreview && (
                        <div className="flex items-center gap-3 p-4 bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-xl animate-fade-in">
                            <span className="material-symbols-outlined text-blue-500 text-lg">info</span>
                            <div className="text-sm text-blue-700 dark:text-blue-300">
                                <span className="font-bold">Schedule Preview: </span>
                                {cronPreview}
                            </div>
                        </div>
                    )}

                    {/* Scan Name */}
                    <div className="flex flex-col gap-3">
                        <label className="text-sm font-bold text-slate-900 dark:text-white">
                            Scan Name (Optional)
                        </label>
                        <input
                            type="text"
                            className="w-full px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
                            placeholder="e.g., Production API Security Check"
                            value={scanName}
                            onChange={(e) => setScanName(e.target.value)}
                        />
                    </div>
                </form>

                {/* Footer Actions */}
                <div className="px-8 py-5 bg-slate-50 dark:bg-slate-900/50 border-t border-slate-200 dark:border-slate-800 flex justify-end gap-4">
                    <button
                        type="button"
                        onClick={onClose}
                        className="px-6 py-2.5 rounded-xl font-bold text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800 transition-all"
                        disabled={isSubmitting}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleSubmit}
                        className="px-8 py-2.5 rounded-xl font-bold text-white bg-emerald-600 hover:bg-emerald-700 shadow-lg shadow-emerald-500/20 active:scale-95 transition-all flex items-center gap-2"
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? (
                            <>
                                <span className="material-symbols-outlined text-xl animate-spin">progress_activity</span>
                                Processing...
                            </>
                        ) : (
                            <>
                                <span className="material-symbols-outlined text-xl">event</span>
                                Schedule Scan
                            </>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
}
