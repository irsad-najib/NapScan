import type { Metadata, Viewport } from "next";
import Script from "next/script";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export const metadata: Metadata = {
  title: "NapScan",
  description: "Security while you Nap",
  keywords: ["NapScan", "Security", "Scanner", "NapScan Security", "NapScan Scanner"],
  openGraph: {
    title: "NapScan",
    description: "Security while you Nap",
    images: ["/napscan-logo.png"],
  },
};

import { ScanProvider } from "@/context/ScanContext";
import { ScheduleProvider } from "@/context/ScheduleContext";
import { AuthProvider } from "@/context/AuthContext";
import { ThemeProvider } from "@/context/ThemeContext";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* Google Fonts: Manrope */}
        <link href="https://fonts.googleapis.com" rel="preconnect" />
        <link crossOrigin="" href="https://fonts.gstatic.com" rel="preconnect" />
        <link
          href="https://fonts.googleapis.com/css2?family=Manrope:wght@200..800&display=swap"
          rel="stylesheet"
        />
        {/* Material Symbols */}
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap"
          rel="stylesheet"
        />
        {/* Tailwind CSS Config */}
        <style>{`
          /* Custom scrollbar for dark mode */
          ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
          }
          ::-webkit-scrollbar-track {
            background: #111722;
          }
          ::-webkit-scrollbar-thumb {
            background: #324467;
            border-radius: 4px;
          }
          ::-webkit-scrollbar-thumb:hover {
            background: #4b628b;
          }
        `}</style>
      </head>
      <body className="bg-background-light dark:bg-background-dark font-display text-slate-900 dark:text-white antialiased overflow-hidden">
        {/* Google Sign-In Script */}
        <Script
          src="https://accounts.google.com/gsi/client"
          strategy="afterInteractive"
        />
        <AuthProvider>
          <ThemeProvider>
            <ScanProvider>
              <ScheduleProvider>
                {children}
              </ScheduleProvider>
            </ScanProvider>
          </ThemeProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
