import { ApiResult, request } from "./http";

export interface Schedule {
    id: string;
    name: string;
    target: string;
    tool: string; // comma-separated tools, e.g. "nmap,zap,openvas"
    cron_expression: string;
    is_active: boolean;
    last_run: string | null;
    last_run_status?: "success" | "failed" | "running";
    last_resource_id?: string;
    next_run: string | null;
    user_id: string;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
}

export interface CreateScheduleRequest {
    name: string;
    target: string;
    tool: string; // comma-separated tools
    cron_expression: string;
}

export const schedulerApi = {
    // List all scheduled scans
    list: async (): Promise<ApiResult<{ success: boolean; message: string; data: Schedule[] }>> =>
        request<{ success: boolean; message: string; data: Schedule[] }>({
            method: "GET",
            url: "/api/schedule",
        }),

    // Create a new scheduled scan
    create: async (data: CreateScheduleRequest): Promise<ApiResult<unknown>> =>
        request<unknown>({
            method: "POST",
            url: "/api/schedule",
            data,
        }),

    // Delete a scheduled scan
    delete: async (id: string): Promise<ApiResult<unknown>> =>
        request<unknown>({
            method: "DELETE",
            url: `/api/schedule/${id}`,
        }),

    // Pause a scheduled scan
    pause: async (id: string): Promise<ApiResult<unknown>> =>
        request<unknown>({
            method: "POST",
            url: `/api/schedule/${id}/pause`,
        }),

    // Resume a scheduled scan
    resume: async (id: string): Promise<ApiResult<unknown>> =>
        request<unknown>({
            method: "POST",
            url: `/api/schedule/${id}/resume`,
        }),
};
