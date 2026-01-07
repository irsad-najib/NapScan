import { ApiResult, request } from "./http";

export type ToolKey = "nmap" | "zap" | "openvas" | "nuclei" | "sslyze" | "ffuf";

export type NmapScanResponse = {
  tcp: unknown;
  udp: unknown;
};

export type NucleiScanResponse = {
  target: string;
  results: Array<Record<string, unknown>>;
};

export type ZapScanResponse = {
  target: string;
  zapBase: string;
  spider: { scanId: string };
  active: { scanId: string };
  alertsRaw: unknown;
};

export type OpenVASTaskStatusResponse = {
  taskID: string;
  status: string;
  progress: number;
  reportID?: string;
  rawXML?: string;
};

export type OpenVASStartScanResponse = {
  message: string;
  target: string;
  targetID: string;
  taskID: string;
  scanName: string;
  status: string;
  progress: number;
  reportID?: string;
};

export type OpenVASReportResponse = unknown;

function ensureNonEmptyTarget(target: string): string {
  const t = target.trim();
  if (!t) throw new Error("Target is required");
  return t;
}

export const scannersApi = {
  nmap: {
    scan: async (target: string): Promise<ApiResult<NmapScanResponse>> =>
      request<NmapScanResponse>({
        method: "POST",
        url: "/api/nmap/scan",
        data: { target: ensureNonEmptyTarget(target) },
      }),
  },

  ffuf: {
    scan: async (target: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/ffuf/scan",
        data: { target: ensureNonEmptyTarget(target) },
      }),
  },

  nuclei: {
    scan: async (target: string): Promise<ApiResult<NucleiScanResponse>> =>
      request<NucleiScanResponse>({
        method: "POST",
        url: "/api/nuclei/scan",
        data: { target: ensureNonEmptyTarget(target) },
      }),
  },

  sslyze: {
    scan: async (target: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/sslyze/scan",
        data: { target: ensureNonEmptyTarget(target) },
      }),
  },

  zap: {
    scan: async (target: string): Promise<ApiResult<ZapScanResponse>> =>
      request<ZapScanResponse>({
        method: "POST",
        url: "/api/zap/scan",
        data: { target: ensureNonEmptyTarget(target) },
      }),
  },

  openvas: {
    version: async (): Promise<ApiResult<string>> =>
      request<string>({
        method: "GET",
        url: "/api/openvas/version",
        responseType: "text",
        headers: {
          Accept: "application/xml,text/xml,text/plain,*/*",
        },
      }),

    scan: async (
      target: string,
      name?: string
    ): Promise<ApiResult<OpenVASStartScanResponse>> =>
      request<OpenVASStartScanResponse>({
        method: "POST",
        url: "/api/openvas/scan",
        data: {
          target: ensureNonEmptyTarget(target),
          ...(name && name.trim() ? { name: name.trim() } : {}),
        },
      }),

    taskStatus: async (
      taskId: string
    ): Promise<ApiResult<OpenVASTaskStatusResponse>> =>
      request<OpenVASTaskStatusResponse>({
        method: "GET",
        url: `/api/openvas/task/${encodeURIComponent(taskId)}/status`,
      }),

    report: async (
      reportId: string
    ): Promise<ApiResult<OpenVASReportResponse>> =>
      request<OpenVASReportResponse>({
        method: "GET",
        url: `/api/openvas/report/${encodeURIComponent(reportId)}`,
      }),
  },
} as const;
