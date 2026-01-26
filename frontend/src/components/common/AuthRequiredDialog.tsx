"use client";

import React from "react";
import { useAuth } from "@/context/AuthContext";

interface AuthRequiredDialogProps {
    isOpen: boolean;
    onClose: () => void;
}

export function AuthRequiredDialog({ isOpen, onClose }: AuthRequiredDialogProps) {
    const { login } = useAuth();

    if (!isOpen) return null;

    const handleLogin = () => {
        login();
        onClose();
    };

    return (
        <div className="fixed inset-0 z-[1000] flex items-center justify-center p-4">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
                onClick={onClose}
            />

            {/* Dialog */}
            <div className="relative bg-white dark:bg-slate-900 w-full max-w-md rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden transform transition-all scale-100 opacity-100">
                <div className="p-6 flex flex-col items-center text-center">

                    {/* Icon */}
                    <div className="w-16 h-16 bg-blue-50 dark:bg-blue-900/20 rounded-full flex items-center justify-center mb-6">
                        <span className="material-symbols-outlined text-3xl text-blue-600 dark:text-blue-400">
                            lock
                        </span>
                    </div>

                    <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                        Authentication Required
                    </h3>

                    <p className="text-slate-600 dark:text-slate-400 mb-8 max-w-[80%]">
                        You need to be signed in to perform security scans. Please sign in to continue.
                    </p>

                    <div className="flex gap-3 w-full">
                        <button
                            onClick={onClose}
                            className="flex-1 py-3 px-4 rounded-xl font-semibold text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleLogin}
                            className="flex-1 py-3 px-4 rounded-xl font-bold text-white bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 shadow-lg shadow-blue-600/20 transition-all hover:scale-[1.02]"
                        >
                            Sign In
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
