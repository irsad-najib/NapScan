"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { handleGoogleCallback } from "@/services/authService";
import { useAuth } from "@/context/AuthContext";

export default function GoogleCallbackPage() {
    const router = useRouter();
    const { refreshUser } = useAuth();
    const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        async function processCallback() {
            try {
                const result = await handleGoogleCallback();
                if (result) {
                    setStatus("success");
                    // Refresh auth context
                    if (refreshUser) {
                        refreshUser();
                    }
                    // Redirect to home after short delay
                    setTimeout(() => {
                        router.push("/");
                    }, 1500);
                } else {
                    setStatus("error");
                    setErrorMessage("Failed to authenticate with Google");
                }
            } catch (error) {
                setStatus("error");
                setErrorMessage(error instanceof Error ? error.message : "Authentication failed");
            }
        }

        processCallback();
    }, [router, refreshUser]);

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-blue-50 dark:from-slate-950 dark:to-slate-900">
            <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl p-8 max-w-md w-full mx-4 text-center">
                {status === "loading" && (
                    <>
                        <div className="mb-6">
                            <div className="size-16 mx-auto bg-blue-100 dark:bg-blue-500/20 rounded-full flex items-center justify-center">
                                <span className="material-symbols-outlined text-3xl text-blue-600 dark:text-blue-400 animate-spin">
                                    progress_activity
                                </span>
                            </div>
                        </div>
                        <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                            Completing Sign In...
                        </h2>
                        <p className="text-slate-500 dark:text-slate-400">
                            Please wait while we authenticate your account.
                        </p>
                    </>
                )}

                {status === "success" && (
                    <>
                        <div className="mb-6">
                            <div className="size-16 mx-auto bg-emerald-100 dark:bg-emerald-500/20 rounded-full flex items-center justify-center">
                                <span className="material-symbols-outlined text-3xl text-emerald-600 dark:text-emerald-400">
                                    check_circle
                                </span>
                            </div>
                        </div>
                        <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                            Sign In Successful!
                        </h2>
                        <p className="text-slate-500 dark:text-slate-400">
                            Redirecting you to the dashboard...
                        </p>
                    </>
                )}

                {status === "error" && (
                    <>
                        <div className="mb-6">
                            <div className="size-16 mx-auto bg-red-100 dark:bg-red-500/20 rounded-full flex items-center justify-center">
                                <span className="material-symbols-outlined text-3xl text-red-600 dark:text-red-400">
                                    error
                                </span>
                            </div>
                        </div>
                        <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
                            Authentication Failed
                        </h2>
                        <p className="text-slate-500 dark:text-slate-400 mb-6">
                            {errorMessage}
                        </p>
                        <button
                            onClick={() => router.push("/")}
                            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
                        >
                            Return to Home
                        </button>
                    </>
                )}
            </div>
        </div>
    );
}
