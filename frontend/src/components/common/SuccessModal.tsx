import React from "react";

interface SuccessModalProps {
    isOpen: boolean;
    onClose: () => void;
    title?: string;
    message: string;
    type?: "success" | "error" | "info";
}

export default function SuccessModal({
    isOpen,
    onClose,
    title = "Success",
    message,
    type = "success",
}: SuccessModalProps) {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-fade-in">
            <div
                className="bg-white dark:bg-slate-900 rounded-2xl shadow-xl w-full max-w-sm overflow-hidden animate-scale-in"
                onClick={(e) => e.stopPropagation()}
            >
                <div className={`p-6 flex flex-col items-center text-center gap-4 border-b-4 ${type === "success" ? "border-green-500" : type === "error" ? "border-red-500" : "border-blue-500"
                    }`}>
                    <div className={`p-3 rounded-full ${type === "success" ? "bg-green-100 text-green-600 dark:bg-green-500/10 dark:text-green-400" :
                            type === "error" ? "bg-red-100 text-red-600 dark:bg-red-500/10 dark:text-red-400" :
                                "bg-blue-100 text-blue-600 dark:bg-blue-500/10 dark:text-blue-400"
                        }`}>
                        <span className="material-symbols-outlined text-3xl">
                            {type === "success" ? "check_circle" : type === "error" ? "error" : "info"}
                        </span>
                    </div>

                    <div className="flex flex-col gap-1">
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                            {title}
                        </h3>
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                            {message}
                        </p>
                    </div>
                </div>

                <div className="p-4 bg-slate-50 dark:bg-slate-800/50">
                    <button
                        onClick={onClose}
                        className="w-full py-2.5 bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-semibold rounded-xl hover:opacity-90 transition-opacity"
                    >
                        Okay
                    </button>
                </div>
            </div>
        </div>
    );
}
