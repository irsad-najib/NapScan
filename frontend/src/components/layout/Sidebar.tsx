"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";

const navItems = [
    { label: "Dashboard", icon: "dashboard", href: "/" },
    { label: "Scans", icon: "radar", href: "/scans" },
    { label: "Schedules", icon: "calendar_month", href: "/schedules" },
    { label: "Reports", icon: "description", href: "/reports" },
    { label: "Settings", icon: "settings", href: "/settings" },
];


export default function Sidebar() {
    const pathname = usePathname();

    const isActive = (href: string) => {
        if (href === "/") return pathname === "/";
        return pathname.startsWith(href);
    };

    return (
        <aside className="w-64 bg-white dark:bg-slate-900 border-r-2 border-slate-200 dark:border-slate-800 flex-col hidden md:flex shrink-0 transition-all duration-300">
            <div className="h-full flex flex-col justify-between p-6">
                <div className="flex flex-col gap-8">
                    {/* Logo */}
                    <div className="flex items-center gap-3 px-2">
                        <Image
                            src="/napscan-logo.png"
                            alt="NapScan Logo"
                            width={44}
                            height={44}
                            className="rounded-lg"
                        />
                        <div className="flex flex-col">
                            <h1 className="text-slate-900 dark:text-white text-base font-bold leading-tight">
                                NapScan
                            </h1>
                            <p className="text-slate-500 dark:text-slate-400 text-xs">
                                Security Scanner
                            </p>
                        </div>
                    </div>

                    {/* Nav Items */}
                    <nav className="flex flex-col gap-2">
                        {navItems.map((item) => (
                            <Link
                                key={item.label}
                                href={item.href}
                                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${isActive(item.href)
                                    ? "bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/20"
                                    : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200"
                                    }`}
                            >
                                <span
                                    className={`material-symbols-outlined text-xl transition-transform ${isActive(item.href)
                                        ? "fill-current scale-110"
                                        : "group-hover:scale-110"
                                        }`}
                                >
                                    {item.icon}
                                </span>
                                <span
                                    className={`text-sm font-semibold tracking-wide ${isActive(item.href)
                                        ? "text-white"
                                        : "text-slate-700 dark:text-slate-300"
                                        }`}
                                >
                                    {item.label}
                                </span>
                            </Link>
                        ))}
                    </nav>
                </div>

                {/* Bottom Section: Help & User Profile */}
                <div className="flex flex-col gap-2">

                    {/* Upgrade Plan Button */}
                    <button className="flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-blue-600 to-cyan-500 hover:from-blue-700 hover:to-cyan-600 text-white rounded-xl font-semibold text-sm shadow-lg shadow-blue-500/20 transition-all duration-200 hover:shadow-blue-500/30 mt-2">
                        <span className="material-symbols-outlined text-lg">
                            rocket_launch
                        </span>
                        Upgrade Plan
                    </button>
                </div>
            </div>
        </aside>
    );
}

