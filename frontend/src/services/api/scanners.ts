import { ApiResult, request } from "./http";

export type ToolKey = "nmap" | "zap" | "openvas" | "nuclei" | "sslyze" | "ffuf" | "mobsf" | "frida";

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

// MobSF Types - New async flow with user decision
export type MobSFFileStatus =
  | "UPLOADED"
  | "MOBSF_RUNNING"
  | "WAITING_USER_DECISION"
  | "FRIDA_RUNNING"
  | "COMPLETED"
  | "FAILED";

export type MobSFUploadData = {
  batch_id: string;
  file_id: number;
  file_name: string;
  hash: string;
  status: MobSFFileStatus;
};

export type MobSFUploadResponse = {
  success: boolean;
  message: string;
  data: MobSFUploadData;
};

// MobSF Findings structure
export type MobSFFindingSeverity = {
  high?: number;
  warning?: number;
  info?: number;
  hotspot?: number;
  secure?: number;
};

export type MobSFFinding = {
  title: string;
  description: string;
  severity?: string;
  section?: string;
  rule?: string;
};

export type MobSFFindings = {
  mobsf: {
    identity: {
      app_name: string;
      package_name: string;
      file_name: string;
      version_name: string;
      icon_path?: string;
    };
    findings: {
      security_score: string;
      totals: MobSFFindingSeverity;
      high: MobSFFinding[];
      warning: MobSFFinding[];
      info: MobSFFinding[];
      hotspot?: MobSFFinding[];
      secure?: MobSFFinding[];
    };
    permissions: {
      status_counts: {
        dangerous: number;
        normal: number;
        unknown: number;
      };
      dangerous_sample: Array<{
        permission: string;
        description: string;
        info: string;
        protection: string;
      }>;
    };
    hashes: {
      md5: string;
      sha1: string;
      sha256: string;
    };
    sdk: {
      min_sdk: string;
      target_sdk: string;
      max_sdk?: string;
    };
    components: {
      activities: number;
      services: number;
      receivers: number;
      providers: number;
      exported_count: {
        exported_activities: number;
        exported_services: number;
        exported_receivers: number;
        exported_providers: number;
      };
    };
    network: {
      domains_total: number;
      urls_total: number;
      domains_sample: string[];
      suspicious_domains: string[];
    };
    trackers: {
      detected_trackers: number;
      total_trackers: number;
    };
    secrets: {
      total: number;
      sample: string[];
    };
  };
};

export type MobSFFileStatusResponse = {
  success: boolean;
  message: string;
  data: {
    id: number;
    batch_id: string;
    file_name: string;
    hash: string;
    status: MobSFFileStatus;
    severity?: string;
    error?: string;
    findings?: MobSFFindings;
    created_at: string;
    updated_at: string;
  };
};

export type MobSFDecisionRequest = {
  decision: "STOP" | "CONTINUE";
};

export type MobSFDecisionResponse = {
  success: boolean;
  message: string;
  data: {
    status: MobSFFileStatus;
  };
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

export type BatchItem = {
  batch_id: string;
  target: string;
  risk_score: number;
  risk_level: string;
  status: string;
  timestamp: string;
};

export type BatchListResponse = BatchItem[];

// Batch Detail Types
export type BatchRiskDetail = {
  scanner: string;
  normalized_severity: string;
  score: number;
  description: string;
  findings: any[];
};

export type BatchScanResult = {
  id: number;
  tool: string;
  target: string;
  summary: any;
  created_at: string;
};

export type BatchDetailResponse = {
  batch_id: string;
  user_id: string;
  status: string;
  created_at: string;
  target: string;
  risk_score: number;
  risk_level: string;
  risk_detail: BatchRiskDetail[];
  scan_results: BatchScanResult[];
};

// Batch API
export const batchApi = {
  create: async (): Promise<ApiResult<BatchCreateResponse>> =>
    request<BatchCreateResponse>({
      method: "POST",
      url: "/api/batch/create",
      // No body required
    }),

  list: async (): Promise<ApiResult<BatchListResponse>> =>
    request<BatchListResponse>({
      method: "GET",
      url: "/api/batch/list",
    }),

  get: async (batchId: string): Promise<ApiResult<BatchDetailResponse>> =>
    request<BatchDetailResponse>({
      method: "GET",
      url: `/api/batch/${batchId}`,
    }),

  report: async (batchId: string): Promise<ApiResult<Blob>> =>
    request<Blob>({
      method: "GET",
      url: `/api/batch/${batchId}/report`,
      responseType: "blob",
    }),
};

export const scannersApi = {
  nmap: {
    // Legacy sync scan
    scan: async (target: string, batchId?: string): Promise<ApiResult<NmapScanResponse>> =>
      request<NmapScanResponse>({
        method: "POST",
        url: "/api/nmap/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Async scan - Start scan and get task_id
    scanAsync: async (target: string, batchId?: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        progress: number;
        status: string;
        task_id: string;
      };
    }>> =>
      request({
        method: "POST",
        url: "/api/nmap/scan/async",
        data: {
          target: ensureNonEmptyTarget(target),
          scan_type: "parallel",
          ...(batchId && { batch_id: batchId }),
        },
      }),

    // Get task status
    taskStatus: async (taskId: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        batch_id: string;
        task_id: string;
        user_id: string;
        target: string;
        status: string;
        progress: number;
        error: string | null;
        result: unknown[];
        started_at: string;
        updated_at: string;
      };
    }>> =>
      request({
        method: "GET",
        url: `/api/nmap/scan/${encodeURIComponent(taskId)}/status`,
      }),

    // Stop scan
    stop: async (taskId: string): Promise<ApiResult<{ success: boolean; message: string }>> =>
      request({
        method: "POST",
        url: `/api/nmap/scan/${encodeURIComponent(taskId)}/stop`,
      }),
  },

  ffuf: {
    // Legacy sync scan
    scan: async (target: string, batchId?: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/ffuf/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Async scan - Start scan and get task_id
    scanAsync: async (target: string, batchId?: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        progress: number;
        status: string;
        task_id: string;
      };
    }>> =>
      request({
        method: "POST",
        url: "/api/ffuf/scan/async",
        data: {
          target: ensureNonEmptyTarget(target),
          ...(batchId && { batch_id: batchId }),
        },
      }),

    // Get task status
    taskStatus: async (taskId: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        batch_id: string;
        task_id: string;
        user_id: string;
        target: string;
        status: string;
        progress: number;
        error: string | null;
        result: unknown[];
        started_at: string;
        updated_at: string;
      };
    }>> =>
      request({
        method: "GET",
        url: `/api/ffuf/scan/${encodeURIComponent(taskId)}/status`,
      }),

    // Stop scan
    stop: async (taskId: string): Promise<ApiResult<{ success: boolean; message: string }>> =>
      request({
        method: "POST",
        url: `/api/ffuf/scan/${encodeURIComponent(taskId)}/stop`,
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
    // Legacy sync scan
    scan: async (target: string, batchId?: string): Promise<ApiResult<unknown>> =>
      request<unknown>({
        method: "POST",
        url: "/api/sslyze/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Async scan - Start scan and get task_id
    scanAsync: async (target: string, batchId?: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        progress: number;
        status: string;
        task_id: string;
      };
    }>> =>
      request({
        method: "POST",
        url: "/api/sslyze/scan/async",
        data: {
          target: ensureNonEmptyTarget(target),
          ...(batchId && { batch_id: batchId }),
        },
      }),

    // Get task status
    taskStatus: async (taskId: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        batch_id: string;
        task_id: string;
        user_id: string;
        target: string;
        status: string;
        progress: number;
        error: string | null;
        result: unknown[];
        started_at: string;
        updated_at: string;
      };
    }>> =>
      request({
        method: "GET",
        url: `/api/sslyze/scan/${encodeURIComponent(taskId)}/status`,
      }),

    // Stop scan
    stop: async (taskId: string): Promise<ApiResult<{ success: boolean; message: string }>> =>
      request({
        method: "POST",
        url: `/api/sslyze/scan/${encodeURIComponent(taskId)}/stop`,
      }),
  },

  zap: {
    // Legacy sync scan
    scan: async (target: string, batchId?: string): Promise<ApiResult<ZapScanResponse>> =>
      request<ZapScanResponse>({
        method: "POST",
        url: "/api/zap/scan",
        data: { target: ensureNonEmptyTarget(target), ...(batchId && { batch_id: batchId }) },
      }),

    // Async scan - Start scan and get task_id
    scanAsync: async (target: string, batchId?: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        progress: number;
        status: string;
        task_id: string;
      };
    }>> =>
      request({
        method: "POST",
        url: "/api/zap/scan/async",
        data: {
          target: ensureNonEmptyTarget(target),
          ...(batchId && { batch_id: batchId }),
        },
      }),

    // Get task status
    taskStatus: async (taskId: string): Promise<ApiResult<{
      success: boolean;
      message: string;
      data: {
        batch_id: string;
        task_id: string;
        user_id: string;
        target: string;
        status: string;
        progress: number;
        error: string | null;
        result: unknown[];
        started_at: string;
        updated_at: string;
      };
    }>> =>
      request({
        method: "GET",
        url: `/api/zap/scan/${encodeURIComponent(taskId)}/status`,
      }),

    // Stop scan
    stop: async (taskId: string): Promise<ApiResult<{ success: boolean; message: string }>> =>
      request({
        method: "POST",
        url: `/api/zap/scan/${encodeURIComponent(taskId)}/stop`,
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
    // Step 1: Upload APK file - triggers MobSF scan automatically
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

    // Step 2: Poll file status until WAITING_USER_DECISION or COMPLETED
    fileStatus: async (fileId: number): Promise<ApiResult<MobSFFileStatusResponse>> =>
      request<MobSFFileStatusResponse>({
        method: "GET",
        url: `/api/files/${fileId}/status`,
      }),

    // Step 3: Submit user decision (STOP or CONTINUE with Frida)
    submitDecision: async (
      fileId: number,
      decision: "STOP" | "CONTINUE"
    ): Promise<ApiResult<MobSFDecisionResponse>> =>
      request<MobSFDecisionResponse>({
        method: "POST",
        url: `/api/files/${fileId}/decision`,
        data: { decision },
      }),
  },

  // Global Active Scans
  getActiveScans: async (): Promise<ApiResult<Array<{
    task_id: string;
    batch_id: string;
    user_id: string;
    target: string;
    tool: string;
    status: string;
    progress: number;
    started_at: string;
    updated_at: string;
  }>>> =>
    request({
      method: "GET",
      url: "/api/scan/active",
    }),
} as const;
