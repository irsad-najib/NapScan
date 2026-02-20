"use client";

import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";

import { useLayout } from "@/context/LayoutContext";

interface HeaderProps {
  title?: string;
  showSearch?: boolean;
  searchPlaceholder?: string;
  onSearch?: (query: string) => void;
  searchValue?: string;
}

export default function Header({
  title,
  showSearch = true,
  searchPlaceholder = "Search...",
  onSearch,
  searchValue,
}: HeaderProps) {
  const { user, isAuthenticated, loading: authLoading, loginWithPopup, logout } = useAuth();
  const { toggleSidebar } = useLayout();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsMenuOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    setIsMenuOpen(false);
  };

  return (
    <header className="h-16 flex items-center justify-between px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 backdrop-blur-sm shrink-0 z-10">
      {/* Mobile menu */}
      <button
        onClick={toggleSidebar}
        className="md:hidden text-slate-600 dark:text-slate-400 hover:text-blue-500 transition-colors mr-4"
      >
        <span className="material-symbols-outlined">menu</span>
      </button>

      {/* Title or Search */}
      {showSearch ? (
        <div className="hidden md:flex items-center bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 px-4 py-2 w-72 focus-within:ring-2 focus-within:ring-blue-500/50 focus-within:border-transparent transition-all hover:border-slate-300 dark:hover:border-slate-600">
          <span className="material-symbols-outlined text-slate-400 text-[20px]">
            search
          </span>
          <input
            className="bg-transparent border-none text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-400 focus:ring-0 w-full ml-3 h-6 font-medium"
            placeholder={searchPlaceholder}
            type="text"
            value={searchValue}
            onChange={(e) => onSearch?.(e.target.value)}
          />
        </div>
      ) : title ? (
        <h1 className="text-lg font-bold text-slate-900 dark:text-white hidden md:block">
          {title}
        </h1>
      ) : (
        <div className="hidden md:block" />
      )}

      {/* Right Actions */}
      <div className="flex items-center gap-4 ml-auto">
        {/* Notifications */}
        <button className="relative p-2.5 text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-xl transition-all duration-200">
          <span className="material-symbols-outlined text-xl">
            notifications
          </span>
          <span className="absolute top-2 right-2 size-2 bg-red-500 rounded-full border-2 border-white dark:border-slate-950 shadow-md"></span>
        </button>

        <div className="h-6 w-px bg-slate-200 dark:bg-slate-700"></div>

        {/* Login/User Section */}
        {authLoading ? (
          <div className="flex items-center justify-center px-5 py-2.5">
            <div className="animate-spin rounded-full h-5 w-5 border-2 border-blue-500 border-t-transparent" />
          </div>
        ) : !isAuthenticated ? (
          <button
            onClick={loginWithPopup}
            className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold py-2.5 px-5 rounded-xl shadow-lg shadow-blue-500/25 transition-all transform hover:scale-105 active:scale-95">
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path
                fill="currentColor"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="currentColor"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="currentColor"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="currentColor"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            <span>Sign In</span>
          </button>
        ) : (
          <div ref={menuRef} className="relative">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="flex items-center gap-3 hover:opacity-80 transition-opacity cursor-pointer"
            >
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300 hidden sm:block">
                {user?.name?.split(" ")[0]}
              </span>
              <img
                src={user?.picture || "/default-avatar.png"}
                alt={user?.name || "User"}
                className="size-9 rounded-full ring-2 ring-blue-500/20 object-cover"
              />
            </button>

            {/* Dropdown Menu */}
            {isMenuOpen && (
              <div className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-xl overflow-hidden z-50">
                {/* User Info */}
                <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
                  <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                    {user?.name}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                    {user?.email}
                  </p>
                </div>

                {/* Menu Items */}
                <div className="py-1">
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                  >
                    <span className="material-symbols-outlined text-lg">logout</span>
                    <span className="font-medium">Sign out</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}
