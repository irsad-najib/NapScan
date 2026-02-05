import { useRef, useEffect } from "react";

interface AlertModalProps {
    isOpen: boolean;
    onClose: () => void;
    title: string;
    message: string;
    type?: "info" | "warning" | "error";
}

export function AlertModal({ isOpen, onClose, title, message, type = "warning" }: AlertModalProps) {
    const modalRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleEscape = (e: KeyboardEvent) => {
            if (e.key === "Escape") onClose();
        };

        if (isOpen) {
            document.addEventListener("keydown", handleEscape);
            document.body.style.overflow = "hidden";
        }

        return () => {
            document.removeEventListener("keydown", handleEscape);
            document.body.style.overflow = "unset";
        };
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    const getIcon = () => {
        switch (type) {
            case "error":
                return "error";
            case "warning":
                return "warning";
            case "info":
            default:
                return "info";
        }
    };

    const getColor = () => {
        switch (type) {
            case "error":
                return "text-red-500 bg-red-100 dark:bg-red-500/20";
            case "warning":
                return "text-amber-500 bg-amber-100 dark:bg-amber-500/20";
            case "info":
            default:
                return "text-blue-500 bg-blue-100 dark:bg-blue-500/20";
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in fade-in duration-200">
            <div
                ref={modalRef}
                className="w-full max-w-md bg-white dark:bg-slate-900 rounded-2xl shadow-xl border border-slate-200 dark:border-slate-800 transform transition-all scale-100 animate-in zoom-in-95 duration-200"
            >
                <div className="p-6">
                    <div className="flex items-start gap-4">
                        <div className={`p-3 rounded-full shrink-0 ${getColor()}`}>
                            <span className="material-symbols-outlined text-2xl">
                                {getIcon()}
                            </span>
                        </div>
                        <div className="flex-1">
                            <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                                {title}
                            </h3>
                            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                                {message}
                            </p>
                        </div>
                    </div>

                    <div className="mt-6 flex justify-end">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 bg-slate-900 dark:bg-white text-white dark:text-slate-900 text-sm font-semibold rounded-lg hover:opacity-90 transition-opacity"
                        >
                            OK, Got it
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
