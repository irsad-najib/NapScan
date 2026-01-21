"use client";

import React, { createContext, useContext, useEffect, useState } from "react";

type Theme = "light" | "dark" | "system";

interface ThemeContextType {
    theme: Theme;
    setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [theme, setTheme] = useState<Theme>("dark");
    const [mounted, setMounted] = useState(false);

    // Initial load from localStorage
    useEffect(() => {
        setMounted(true);
        const stored = localStorage.getItem("napscan-theme") as Theme | null;
        if (stored) {
            setTheme(stored);
        } else {
            setTheme("system");
        }
    }, []);

    // Apply theme change
    useEffect(() => {
        if (!mounted) return;

        const root = document.documentElement;
        let effectiveTheme: "light" | "dark" = "dark";

        if (theme === "system") {
            effectiveTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
        } else {
            effectiveTheme = theme;
        }

        if (effectiveTheme === "dark") {
            root.classList.add("dark");
            root.classList.remove("light");
        } else {
            root.classList.remove("dark");
            root.classList.add("light");
        }

        localStorage.setItem("napscan-theme", theme);
    }, [theme, mounted]);

    // Listen for system preference changes
    useEffect(() => {
        if (theme !== "system") return;

        const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
        const handleChange = () => {
            const root = document.documentElement;
            const newTheme = mediaQuery.matches ? "dark" : "light";

            if (newTheme === "dark") {
                root.classList.add("dark");
                root.classList.remove("light");
            } else {
                root.classList.remove("dark");
                root.classList.add("light");
            }
        };

        mediaQuery.addEventListener("change", handleChange);
        return () => mediaQuery.removeEventListener("change", handleChange);
    }, [theme]);

    return (
        <ThemeContext.Provider value={{ theme, setTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}

export function useTheme() {
    const context = useContext(ThemeContext);
    if (context === undefined) {
        throw new Error("useTheme must be used within a ThemeProvider");
    }
    return context;
}
