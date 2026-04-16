export type ActivityEventSource = "finding" | "system";

export type ActivityEventKind =
  | "status_change"
  | "review_note"
  | "decision"
  | "lifecycle"
  | "ingest"
  | "sync"
  | "export"
  | "asset"
  | "system";

export interface ActivityEvent {
  id: string;
  source: ActivityEventSource;
  kind: ActivityEventKind;
  eventType: string;
  timestamp: string;
  title: string;
  detail?: string;
  findingId?: string;
  relatedFindingIds?: string[];
  relatedFindings?: Array<{
    id: string;
    title: string;
    severity?: string;
    timestamp: string;
    assetId?: string;
    assetName?: string;
  }>;
  assetId?: string;
  assetName?: string;
  severity?: string;
}

