"use client";

import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";

export default function UserMenu() {
    const { user, logout, isAuthenticated } = useAuth();
    const [isOpen, setIsOpen] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);

    // Close menu when clicking outside
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        }

        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    if (!isAuthenticated || !user) {
        return null;
    }

    const handleLogout = () => {
        logout();
        setIsOpen(false);
    };

    return (
        <div ref={menuRef} className="relative">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-3 px-4 py-4 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800/50 cursor-pointer border-t border-slate-200 dark:border-slate-800 pt-5 transition-colors w-full text-left"
            >
                <div
                    className="bg-center bg-no-repeat bg-cover rounded-lg size-9 shrink-0 ring-2 ring-blue-500/20"
                    style={{
                        backgroundImage: user.picture
                            ? `url("${user.picture}")`
                            : undefined,
                        backgroundColor: !user.picture ? "#4285F4" : undefined,
                    }}
                >
                    {!user.picture && (
                        <div className="w-full h-full flex items-center justify-center text-white font-bold text-sm">
                            {user.name?.charAt(0)?.toUpperCase() || "U"}
                        </div>
                    )}
                </div>
                <div className="flex flex-col min-w-0 flex-1">
                    <p className="text-slate-900 dark:text-white text-sm font-semibold truncate">
                        {user.name || "User"}
                    </p>
                    <p className="text-slate-500 dark:text-slate-500 text-xs truncate">
                        {user.email}
                    </p>
                </div>
                <span
                    className={`material-symbols-outlined text-slate-600 dark:text-slate-400 text-lg transition-transform ${isOpen ? "rotate-180" : ""
                        }`}
                >
                    expand_more
                </span>
            </button>

            {/* Dropdown Menu */}
            {isOpen && (
                <div className="absolute bottom-full left-0 right-0 mb-2 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-lg overflow-hidden z-50">
                    <div className="py-1">
                        <button
                            onClick={handleLogout}
                            className="w-full flex items-center gap-3 px-4 py-3 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                        >
                            <span className="material-symbols-outlined text-lg">logout</span>
                            <span className="font-medium">Sign out</span>
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
