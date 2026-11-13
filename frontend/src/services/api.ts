import axios from "axios";
import type {
  DashboardSummary,
  SecurityDecision,
  ApprovalRequest,
  EvaluationMetrics,
  BenchmarkReport,
  EmailSummary,
  EmailRecord,
  EmailListResponse,
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 5000,
});

export const getDashboardSummary = async (): Promise<DashboardSummary> => {
  const res = await api.get<DashboardSummary>("/api/dashboard/summary");
  return res.data;
};

export const getDecisions = async (): Promise<SecurityDecision[]> => {
  const res = await api.get<SecurityDecision[]>("/api/decisions");
  return res.data;
};

export const getApprovals = async (): Promise<ApprovalRequest[]> => {
  const res = await api.get<ApprovalRequest[]>("/api/approvals");
  return res.data;
};

export const getEvaluationMetrics = async (): Promise<EvaluationMetrics> => {
  const res = await api.get<EvaluationMetrics>("/api/evaluation");
  return res.data;
};

export const getBenchmarks = async (): Promise<BenchmarkReport> => {
  const res = await api.get<BenchmarkReport>("/api/benchmarks");
  return res.data;
};

export const approveRequest = async (approvalId: string): Promise<{ status: string }> => {
  const res = await api.post<{ status: string }>(`/approval/${approvalId}/approve`);
  return res.data;
};

export const rejectRequest = async (approvalId: string): Promise<{ status: string }> => {
  const res = await api.post<{ status: string }>(`/approval/${approvalId}/reject`);
  return res.data;
};

export const getAuditEvents = async (): Promise<SecurityDecision[]> => {
  const res = await api.get<SecurityDecision[]>("/api/decisions");
  return res.data;
};

export const getEmailSummary = async (): Promise<EmailSummary> => {
  const res = await api.get<EmailSummary>("/api/emails/summary");
  return res.data;
};

export interface EmailFilterParams {
  page?: number;
  page_size?: number;
  classification?: string;
  risk_level?: string;
  state?: string;
  requires_human_review?: boolean;
  search?: string;
}

export const getEmails = async (params?: EmailFilterParams): Promise<EmailListResponse> => {
  const res = await api.get<EmailListResponse>("/api/emails", { params });
  return res.data;
};

export const getEmailDetail = async (messageId: string): Promise<EmailRecord> => {
  const res = await api.get<EmailRecord>(`/api/emails/${encodeURIComponent(messageId)}`);
  return res.data;
};
