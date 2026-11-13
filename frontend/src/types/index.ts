export interface DashboardSummary {
  total: number;
  allowed: number;
  blocked: number;
  approvals: number;
}

export interface SecurityDecision {
  event_id: string;
  timestamp: string;
  agent_id: string;
  operation: string;
  arguments?: Record<string, any>;
  final_decision: "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
  reason: string;
  downstream_executed: boolean;
  provenance?: { verification: string; decision?: string; source?: string };
  replay?: { decision: string; request_id?: string; reason?: string };
  capability?: { decision: string; capability?: string };
  destination?: { trust: string; destination?: string };
  risk?: { level: string; capability?: string };
  context?: { decision: string; mode?: string };
  approval?: { status: string; approval_id?: string };
}

export interface ApprovalRequest {
  approval_id: string;
  timestamp: string;
  agent_id: string;
  operation: string;
  request_hash: string;
  status: "PENDING" | "APPROVED" | "REJECTED";
}

export interface EvaluationOperator {
  name: string;
  result: string;
}

export interface EvaluationMetrics {
  generated: boolean;
  timestamp?: string | null;
  detection_rate: string | null;
  prevention_rate: string | null;
  false_allow: string | null;
  false_block: string | null;
  mutations_passed: string | null;
  security_tests: string | null;
  operators: EvaluationOperator[];
  raw_report?: {
    timestamp?: string;
    total_cases?: number;
    passed_cases?: number;
    failed_cases?: number;
    confusion_matrix?: {
      true_positives: number;
      true_negatives: number;
      false_positives: number;
      false_negatives: number;
      precision: number;
      recall: number;
      specificity: number;
      f1_score: number;
      accuracy: number;
    };
    operations_summary?: {
      total_operations_evaluated: number;
      allowed_count: number;
      blocked_count: number;
      approval_required_count: number;
      allowed_by_operation: Record<string, number>;
      blocked_by_operation: Record<string, number>;
      approval_required_by_operation: Record<string, number>;
    };
    layer_metrics?: Record<string, number>;
  } | null;
  message?: string;
}

export interface LatencyStats {
  count: number;
  mean_ms: number;
  median_ms: number;
  p90_ms: number;
  p95_ms: number;
  p99_ms: number;
  min_ms: number;
  max_ms: number;
  std_dev_ms: number;
  throughput_ops_per_sec: number;
}

export interface GatewayBenchmarkPath {
  path_id: string;
  name: string;
  description: string;
  decision_path: string;
  expected_decision: string;
  downstream_contact: boolean;
  latency: LatencyStats;
}

export interface MicroBenchmarkStage {
  stage_id: string;
  stage_name: string;
  description: string;
  latency: LatencyStats;
}

export interface BenchmarkReport {
  generated?: boolean;
  timestamp?: string | null;
  environment?: {
    python_version: string;
    os_platform: string;
    architecture: string;
    processor?: string;
    timestamp: string;
    warmup_iterations: number;
    sample_iterations: number;
    high_res_timer: string;
  } | null;
  gateway_benchmarks?: Record<string, GatewayBenchmarkPath>;
  micro_benchmarks?: Record<string, MicroBenchmarkStage>;
  end_to_end_comparison?: Record<string, any>;
  summary_highlights?: Record<string, any>;
  message?: string;
}

export interface EmailSummary {
  total_discovered: number;
  processed: number;
  processing: number;
  discovered: number;
  failed: number;
  classified_count: number;
  by_classification: {
    SAFE: number;
    SUSPICIOUS: number;
    NEEDS_REVIEW: number;
  };
  by_risk_level: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
  };
  requires_human_review_count: number;
  unprocessed_count: number;
}

export interface EmailRecord {
  message_id: string;
  thread_id?: string | null;
  subject: string;
  sender: string;
  date: string;
  snippet: string;
  state: "DISCOVERED" | "PROCESSING" | "PROCESSED" | "FAILED" | string;
  discovered_at: string;
  updated_at: string;
  retry_count: number;
  last_error?: string | null;
  classification?: "SAFE" | "SUSPICIOUS" | "NEEDS_REVIEW" | null;
  risk_level?: "LOW" | "MEDIUM" | "HIGH" | null;
  reasons: string[];
  requires_human_review: boolean;
  processed_at?: string | null;
  classification_status?: string | null;
  failure_reason?: string | null;
  summary?: string | null;
}

export interface EmailListResponse {
  items: EmailRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}
