import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Risk Management Dashboard",
  description: "SecureScan Admin Console - Security and Risk Management Dashboard",
  viewport: "width=device-width, initial-scale=1.0",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
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
        {children}
      </body>
    </html>
  );
}
