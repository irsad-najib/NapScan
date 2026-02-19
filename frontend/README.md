# NapScan Frontend

Comprehensive web interface for the NapScan automated vulnerability scanning platform. Built with Next.js, React, and Tailwind CSS.
NapScan Frontend provides a user-friendly dashboard for security professionals to manage, schedule, and analyze security scans. It integrates with various security tools (Nmap, ZAP, Nuclei, OpenVAS, MobSF, etc.) and presents their findings in a unified, actionable format.

## Technology Stack

- **Framework:** [Next.js 15](https://nextjs.org/) (App Router)
- **Library:** [React 19](https://react.dev/)
- **Language:** [TypeScript](https://www.typescriptlang.org/)
- **Styling:** [Tailwind CSS 4](https://tailwindcss.com/)
- **State Management:** React Context API
- **Data Fetching:** Axios
- **Icons:** Material Symbols (Google Fonts)
- **Utilities:** `cronstrue` (Cron parsing), `date-fns` (Date formatting)

## Getting Started

### Prerequisites

- Node.js 18+ or 20+ (LTS recommended)

## Project Structure

```
frontend/
├── src/
│   ├── app/              # Next.js App Router pages
│   │   ├── auth/         # Authentication pages (Login, Callback)
│   │   ├── reports/      # Reports management
│   │   ├── scans/        # Scan history and details
│   │   ├── schedules/    # Schedule management
│   │   ├── settings/     # User settings
│   │   └── page.tsx      # Dashboard (Home)
│   ├── components/       # Reusable UI components
│   ├── context/          # React Context providers (Auth, Scan, Schedule)
│   ├── services/         # API services (Axios configuration)
│   └── styles/           # Global styles (Tailwind)
├── public/               # Static assets
└── ...config files       # Next, Tailwind, TypeScript configs
```

## Key Features

### 1. Dashboard
- Real-time overview of system status.
- Recent scan activity and vulnerability statistics.
- Quick actions to start new scans.

### 2. Scan Management (`/scans`)
- **Start Scans:** Configure target, select tools (Nmap, ZAP, Nuclei, SSLyze, FFUF, OpenVAS).
- **Mobile Auditing:** Upload APK files for static (MobSF) and dynamic (Frida) analysis.
- **Results View:** Detailed breakdown of vulnerabilities with severity levels (Critical to Info).
- **Interactive Parsing:** Normalized output from different tools into a consistent table format.

### 3. Scheduling (`/schedules`)
- **Automated Scans:** Schedule scans to run automatically.
- **Frequency Options:** 
  - Once (Specific Date/Time)
  - Recurring: Every 2/6/12 Hours, Daily, Weekly, Monthly.
- **Mobile Support:** Automatically handles APK upload for scheduled mobile scans.
- **Management:** Pause, Resume, or Delete active schedules.

### 4. Reports (`/reports`)
- **Generate Reports:** Create PDF/HTML reports for specific scan batches.
- **Download:** Export scan findings for stakeholders.

### 5. Authentication
- **Secure Access:** Protected routes using Google OAuth / JWT.
- **Session Management:** Automatic token handling and refresh.

