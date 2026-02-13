"use client";

import { useState, useEffect } from "react";
import { Sidebar, Header } from "@/components/layout";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/context/ThemeContext";

type ThemeOption = "light" | "dark" | "system";

interface SettingsSection {
    id: string;
    label: string;
    icon: string;
}

const settingsSections: SettingsSection[] = [
    { id: "general", label: "General", icon: "tune" },
    { id: "notifications", label: "Notifications", icon: "notifications" },
    { id: "account", label: "Account", icon: "person" },
];

export default function SettingsPage() {
    const { user, logout } = useAuth();
    const { theme, setTheme } = useTheme();
    const [activeSection, setActiveSection] = useState("general");
    const [saveMessage, setSaveMessage] = useState<string | null>(null);

    // General Settings
    // Theme is now managed by ThemeContext
    const [autoSave, setAutoSave] = useState(true);

    // Notification Settings
    const [emailNotifications, setEmailNotifications] = useState(true);
    const [scanComplete, setScanComplete] = useState(true);
    const [criticalVulns, setCriticalVulns] = useState(true);
    const [weeklyDigest, setWeeklyDigest] = useState(false);

    // Load settings from localStorage on mount
    useEffect(() => {
        // Load other settings
        const storedAutoSave = localStorage.getItem("napscan-autosave");
        if (storedAutoSave !== null) setAutoSave(storedAutoSave === "true");

        const storedEmailNotif = localStorage.getItem("napscan-email-notifications");
        if (storedEmailNotif !== null) setEmailNotifications(storedEmailNotif === "true");

        const storedScanComplete = localStorage.getItem("napscan-notify-scan-complete");
        if (storedScanComplete !== null) setScanComplete(storedScanComplete === "true");

        const storedCriticalVulns = localStorage.getItem("napscan-notify-critical");
        if (storedCriticalVulns !== null) setCriticalVulns(storedCriticalVulns === "true");

        const storedWeeklyDigest = localStorage.getItem("napscan-weekly-digest");
        if (storedWeeklyDigest !== null) setWeeklyDigest(storedWeeklyDigest === "true");
    }, []);

    const handleThemeChange = (newTheme: ThemeOption) => {
        setTheme(newTheme);
    };

    const handleSave = () => {
        // Save all settings to localStorage
        localStorage.setItem("napscan-theme", theme);
        localStorage.setItem("napscan-autosave", String(autoSave));
        localStorage.setItem("napscan-email-notifications", String(emailNotifications));
        localStorage.setItem("napscan-notify-scan-complete", String(scanComplete));
        localStorage.setItem("napscan-notify-critical", String(criticalVulns));
        localStorage.setItem("napscan-weekly-digest", String(weeklyDigest));

        setSaveMessage("Settings saved successfully!");
        setTimeout(() => setSaveMessage(null), 3000);
    };

    const renderToggle = (
        enabled: boolean,
        onChange: (val: boolean) => void,
        label: string,
        description?: string
    ) => (
        <div className="flex items-center justify-between py-4 border-b border-slate-200 dark:border-slate-700/50 last:border-b-0">
            <div className="flex-1 pr-4">
                <p className="text-sm font-semibold text-slate-900 dark:text-white">{label}</p>
                {description && (
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{description}</p>
                )}
            </div>
            <button
                onClick={() => onChange(!enabled)}
                className={`relative w-12 h-6 rounded-full transition-all duration-200 ${enabled
                    ? "bg-gradient-to-r from-blue-600 to-cyan-500"
                    : "bg-slate-300 dark:bg-slate-600"
                    }`}
            >
                <span
                    className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow-md transition-all duration-200 ${enabled ? "left-7" : "left-1"
                        }`}
                />
            </button>
        </div>
    );

    const renderGeneralSettings = () => (
        <div className="space-y-6">
            {/* Theme */}
            <div>
                <label className="block text-sm font-semibold text-slate-900 dark:text-white mb-3">
                    Theme
                </label>
                <div className="grid grid-cols-3 gap-3">
                    {(["light", "dark", "system"] as ThemeOption[]).map((option) => (
                        <button
                            key={option}
                            onClick={() => handleThemeChange(option)}
                            className={`flex flex-col items-center gap-2 p-4 rounded-xl border-2 transition-all ${theme === option
                                ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10"
                                : "border-slate-200 dark:border-slate-700 hover:border-blue-300 dark:hover:border-blue-600"
                                }`}
                        >
                            <span className={`material-symbols-outlined text-2xl ${theme === option ? "text-blue-600 dark:text-blue-400" : "text-slate-500"
                                }`}>
                                {option === "light" ? "light_mode" : option === "dark" ? "dark_mode" : "contrast"}
                            </span>
                            <span className={`text-sm font-semibold capitalize ${theme === option ? "text-blue-600 dark:text-blue-400" : "text-slate-600 dark:text-slate-400"
                                }`}>
                                {option}
                            </span>
                        </button>
                    ))}
                </div>
                <p className="text-xs text-slate-500 mt-2">
                    {theme === "system" && "Automatically switches based on your system preference"}
                    {theme === "light" && "Light mode - easier on the eyes in bright environments"}
                    {theme === "dark" && "Dark mode - reduces eye strain in low-light environments"}
                </p>
            </div>

            {/* Auto Save */}
            {renderToggle(autoSave, setAutoSave, "Auto-save Scans", "Automatically save scan results when completed")}
        </div>
    );

    const renderNotificationSettings = () => (
        <div className="space-y-2">
            {renderToggle(
                emailNotifications,
                setEmailNotifications,
                "Email Notifications",
                "Receive notifications via email"
            )}

            {emailNotifications && (
                <div className="pl-4 border-l-2 border-blue-500 space-y-2 py-2">
                    {renderToggle(
                        scanComplete,
                        setScanComplete,
                        "Scan Completed",
                        "Notify when a scan finishes"
                    )}
                    {renderToggle(
                        criticalVulns,
                        setCriticalVulns,
                        "Critical Vulnerabilities",
                        "Alert when critical/high severity issues are found"
                    )}
                    {renderToggle(
                        weeklyDigest,
                        setWeeklyDigest,
                        "Weekly Digest",
                        "Receive a weekly summary of all scans"
                    )}
                </div>
            )}
        </div>
    );

    const renderAccountSettings = () => (
        <div className="space-y-6">
            {/* Profile Info */}
            <div className="p-6 bg-gradient-to-br from-blue-50 to-cyan-50 dark:from-slate-800 dark:to-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700">
                <div className="flex items-center gap-4">
                    {user?.picture ? (
                        <img
                            src={user.picture}
                            alt={user.name || "User"}
                            className="w-16 h-16 rounded-full shadow-lg"
                        />
                    ) : (
                        <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white text-2xl font-bold shadow-lg">
                            {user?.name?.charAt(0) || "U"}
                        </div>
                    )}
                    <div className="flex-1">
                        <h4 className="font-bold text-lg text-slate-900 dark:text-white">
                            {user?.name || "Guest User"}
                        </h4>
                        <p className="text-sm text-slate-600 dark:text-slate-400">{user?.email || "Not signed in"}</p>
                    </div>
                    <span className="px-3 py-1 bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-400 rounded-full text-xs font-bold">
                        Free
                         Plan
                    </span>
                </div>
            </div>

            {/* Account Actions
            <div className="space-y-3">
                <button className="w-full flex items-center gap-3 px-4 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-xl text-left transition-colors">
                    <span className="material-symbols-outlined text-slate-500">history</span>
                    <div className="flex-1">
                        <p className="font-semibold text-slate-900 dark:text-white text-sm">Scan History</p>
                        <p className="text-xs text-slate-500">View and manage past scans</p>
                    </div>
                    <span className="material-symbols-outlined text-slate-400">chevron_right</span>
                </button>

                <button className="w-full flex items-center gap-3 px-4 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-xl text-left transition-colors">
                    <span className="material-symbols-outlined text-slate-500">download</span>
                    <div className="flex-1">
                        <p className="font-semibold text-slate-900 dark:text-white text-sm">Export Data</p>
                        <p className="text-xs text-slate-500">Download all your data</p>
                    </div>
                    <span className="material-symbols-outlined text-slate-400">chevron_right</span>
                </button>
            </div> */}

            {/* Danger Zone */}
            <div className="p-4 bg-red-50 dark:bg-red-500/10 rounded-xl border border-red-200 dark:border-red-500/30">
                <h4 className="font-bold text-red-700 dark:text-red-400 mb-4 flex items-center gap-2">
                    <span className="material-symbols-outlined">warning</span>
                    Danger Zone
                </h4>
                <div className="flex flex-col sm:flex-row gap-3">
                    {user && (
                        <button
                            onClick={logout}
                            className="flex items-center justify-center gap-2 px-4 py-2 bg-red-100 dark:bg-red-500/20 hover:bg-red-200 dark:hover:bg-red-500/30 text-red-700 dark:text-red-400 rounded-lg font-semibold text-sm transition-colors"
                        >
                            <span className="material-symbols-outlined text-lg">logout</span>
                            Sign Out
                        </button>
                    )}
                    <button className="flex items-center justify-center gap-2 px-4 py-2 bg-red-100 dark:bg-red-500/20 hover:bg-red-200 dark:hover:bg-red-500/30 text-red-700 dark:text-red-400 rounded-lg font-semibold text-sm transition-colors">
                        <span className="material-symbols-outlined text-lg">delete_forever</span>
                        Delete Account
                    </button>
                </div>
            </div>
        </div>
    );

    const renderContent = () => {
        switch (activeSection) {
            case "general":
                return renderGeneralSettings();
            case "notifications":
                return renderNotificationSettings();
            case "account":
                return renderAccountSettings();
            default:
                return renderGeneralSettings();
        }
    };

    return (
        <div className="flex h-screen w-full overflow-hidden bg-white dark:bg-slate-950">
            {/* Sidebar */}
            <Sidebar />

            {/* Main Layout */}
            <div className="flex-1 flex flex-col h-full overflow-hidden bg-gradient-to-br from-white to-slate-50 dark:from-slate-950 dark:to-slate-900 relative">
                {/* Top Navigation */}
                <Header searchPlaceholder="Search settings..." />

                {/* Main Content */}
                <main className="flex-1 overflow-y-auto overflow-x-hidden px-8 py-10 md:px-12 md:py-12 scroll-smooth">
                    <div className="max-w-5xl mx-auto flex flex-col gap-8 pb-20">
                        {/* Page Header */}
                        <div className="flex flex-col gap-2">
                            <h2 className="text-3xl md:text-4xl font-bold text-slate-900 dark:text-white tracking-tight">
                                Settings
                            </h2>
                            <p className="text-slate-600 dark:text-slate-400 text-base font-medium">
                                Configure your NapScan preferences
                            </p>
                        </div>

                        {/* Save Message Toast */}
                        {saveMessage && (
                            <div className="fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 bg-emerald-500 text-white rounded-xl shadow-lg animate-fade-in">
                                <span className="material-symbols-outlined">check_circle</span>
                                {saveMessage}
                            </div>
                        )}

                        {/* Settings Container */}
                        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                            {/* Settings Navigation */}
                            <div className="lg:col-span-1">
                                <nav className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 p-2 sticky top-6">
                                    {settingsSections.map((section) => (
                                        <button
                                            key={section.id}
                                            onClick={() => setActiveSection(section.id)}
                                            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition-all ${activeSection === section.id
                                                ? "bg-gradient-to-r from-blue-600 to-cyan-500 text-white shadow-lg shadow-blue-500/20"
                                                : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700/50"
                                                }`}
                                        >
                                            <span className="material-symbols-outlined text-xl">
                                                {section.icon}
                                            </span>
                                            <span className="font-semibold text-sm">{section.label}</span>
                                        </button>
                                    ))}
                                </nav>
                            </div>

                            {/* Settings Content */}
                            <div className="lg:col-span-3">
                                <div className="bg-white dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
                                    {/* Section Header */}
                                    <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/30">
                                        <h3 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                            <span className="material-symbols-outlined">
                                                {settingsSections.find((s) => s.id === activeSection)?.icon}
                                            </span>
                                            {settingsSections.find((s) => s.id === activeSection)?.label} Settings
                                        </h3>
                                    </div>

                                    {/* Section Content */}
                                    <div className="p-6">{renderContent()}</div>
                                </div>

                                {/* Save Button */}
                                <div className="flex justify-end mt-6">
                                    <button
                                        onClick={handleSave}
                                        className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold rounded-xl shadow-lg shadow-blue-600/30 transition-all transform hover:scale-105 active:scale-95"
                                    >
                                        <span className="material-symbols-outlined">save</span>
                                        Save Changes
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
}
