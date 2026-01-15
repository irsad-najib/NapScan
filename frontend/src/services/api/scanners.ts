import { ApiResult, request } from "./http";

export type ToolKey = "nmap" | "zap" | "openvas" | "nuclei" | "sslyze" | "ffuf" | "mobsf";

export type NmapScanResponse = {
  tcp: unknown;
  udp: unknown;
};

export type NucleiScanResponse = {
  target: string;
  results: Array<Record<string, unknown>>;
};

// Nuclei Async Result Response
export type NucleiAsyncResultResponse = {
  success: boolean;
  message: string;
  data: {
    batch_id: string;
    compact: boolean;
    results: Array<{
      host: string;
      ip?: string;
      port?: string;
      url?: string;
      "matched-at"?: string;
      "matcher-name"?: string;
      "template-id"?: string;
      type?: string;
      info: {
        name: string;
        description?: string;
        severity: string;
        author?: string[];
        tags?: string[];
        reference?: string[];
        remediation?: string;
        classification?: {
          "cve-id"?: string | null;
          "cwe-id"?: string[] | null;
        };
      };
      request?: string;
      response?: string;
      "curl-command"?: string;
      "extracted-results"?: string[];
      timestamp?: string;
    }>;
  };
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

// MobSF Types
export type MobSFUploadData = {
  file_name: string;
  hash: string;
  scan_type: string;
  upload: {
    analyzer: string;
    file_name: string;
    hash: string;
    scan_type: string;
    status: string;
  };
};

export type MobSFUploadResponse = {
  success: boolean;
  message: string;
  data: MobSFUploadData;
};

export type MobSFScanRequest = {
  hash: string;
  file_name: string;
  scan_type: string;
  batch_id?: string;
};

export type MobSFScanResponse = {
  hash: string;
  scan_type: string;
  file_name: string;
  app_name?: string;
  package_name?: string;
  version_name?: string;
  version_code?: string;
  size?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  permissions?: Record<string, unknown>;
  security_score?: number;
  average_cvss?: number;
  findings?: Array<{
    severity: string;
    title: string;
    description: string;
  }>;
  // Full scan result from MobSF
  [key: string]: unknown;
};

function ensureNonEmptyTarget(target: string): string {
  const t = target.trim();
  if (!t) throw new Error("Target is required");
  return t;
}

// Batch Types
export type BatchCreateResponse = {
  batch_id: string;
};

// Batch API
export const batchApi = {
  create: async (): Promise<ApiResult<BatchCreateResponse>> =>
    request<BatchCreateResponse>({
      method: "POST",
      url: "/api/batch/create",
      // No body required
    }),
};

export const scannersApi = {
  nmap: {
    scan: async (target: string, batchId?: string): Promise<ApiResult<NmapScanResponse>> =>
      request<NmapScanResponse>({
        method: "POST",
        url: "/api/nmap/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),
  },

  ffuf: {
    scan: async (target: string, batchId?: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/ffuf/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),
  },

  nuclei: {
    // Sync scan (legacy)
    scan: async (target: string, batchId?: string): Promise<ApiResult<NucleiScanResponse>> =>
      request<NucleiScanResponse>({
        method: "POST",
        url: "/api/nuclei/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Async scan - Start scan and get task_id
    scanAsync: async (target: string, batchId?: string): Promise<ApiResult<{
      message: string;
      status: string;
      target: string;
      task_id: string;
    }>> =>
      request({
        method: "POST",
        url: "/api/nuclei/scan/async",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Get task status
    taskStatus: async (taskId: string): Promise<ApiResult<{
      batch_id: string;
      progress: number;
      started_at: string;
      status: string;
      target: string;
      task_id: string;
      updated_at: string;
    }>> =>
      request({
        method: "GET",
        url: `/api/nuclei/scan/async/${encodeURIComponent(taskId)}`,
      }),

    // Get final result
    result: async (taskId: string): Promise<ApiResult<NucleiAsyncResultResponse>> =>
      request<NucleiAsyncResultResponse>({
        method: "GET",
        url: `/api/nuclei/scan/async/${encodeURIComponent(taskId)}/result`,
      }),
  },

  sslyze: {
    scan: async (target: string, batchId?: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/sslyze/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),
  },

  zap: {
    scan: async (target: string, batchId?: string): Promise<ApiResult<ZapScanResponse>> =>
      request<ZapScanResponse>({
        method: "POST",
        url: "/api/zap/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
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
      name?: string,
      batchId?: string
    ): Promise<ApiResult<OpenVASStartScanResponse>> =>
      request<OpenVASStartScanResponse>({
        method: "POST",
        url: "/api/openvas/scan",
        data: {
          target: ensureNonEmptyTarget(target),
          ...(name && name.trim() ? { name: name.trim() } : {}),
          ...(batchId && { batch_id: batchId }),
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

  mobsf: {
    // Step 1: Upload APK file
    upload: async (file: File, batchId?: string): Promise<ApiResult<MobSFUploadResponse>> => {
      const formData = new FormData();
      formData.append("file", file);
      if (batchId) {
        formData.append("batch_id", batchId);
      }

      return request<MobSFUploadResponse>({
        method: "POST",
        url: "/api/mobsf/upload",
        data: formData,
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
    },

    // Step 2: Scan using hash, file_name, scan_type from upload
    scan: async (params: MobSFScanRequest): Promise<ApiResult<MobSFScanResponse>> =>
      request<MobSFScanResponse>({
        method: "POST",
        url: "/api/mobsf/scan",
        data: params,
      }),
  },
} as const;
