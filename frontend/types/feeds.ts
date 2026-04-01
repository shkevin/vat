export interface FeedSourceSummary {
  source: string;
  last_status: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_item_count: number;
  last_checksum: string | null;
  record_count: number;
  last_record_at: string | null;
}

export interface FeedRun {
  id: string;
  source: string;
  status: string;
  trace_id: string | null;
  stats: Record<string, unknown>;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface FeedSummaryResponse {
  total_records: number;
  severity_breakdown: Record<string, number>;
  sources: FeedSourceSummary[];
  top_vulnerabilities: Array<{ vulnerability_id: string | null; count: number }>;
}

export interface FeedRunsResponse {
  count: number;
  runs: FeedRun[];
}

export interface FeedRecord {
  id: number;
  source: string;
  record_key: string;
  vulnerability_id: string | null;
  aliases: string[];
  package_name: string | null;
  ecosystem: string | null;
  version: string | null;
  severity: string | null;
  title: string | null;
  details: Record<string, unknown>;
  published_at: string | null;
  modified_at: string | null;
  fetched_at: string | null;
  run_id: string | null;
}

export interface FeedRecordsResponse {
  total: number;
  count: number;
  records: FeedRecord[];
}
