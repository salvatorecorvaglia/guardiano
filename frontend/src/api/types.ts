/**
 * API types, generated from the backend's OpenAPI schema (src/api/schema.d.ts).
 * Regenerate after backend schema changes with `pnpm gen:api`; CI fails when they drift.
 */
import type { components, paths } from "./schema";

type S = components["schemas"];

export type Role = S["Role"];
export type Severity = S["Severity"];
export type Criticality = S["Criticality"];
export type Status = S["Status"];
export type FindingType = S["ScanType"];
export type EventType = S["EventType"];

export type User = S["UserOut"];
export type UserBrief = S["UserBrief"];
export type LoginResponse = S["LoginResponse"];

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export type AssetRef = S["AssetRef"];
export type SeverityCounts = S["SeverityCounts"];
export type Asset = S["AssetSummary"];
export type Scan = S["ScanOut"];
export type Finding = S["FindingOut"];
export type FindingEvent = S["FindingEventOut"];
export type AcceptanceRequest = S["AcceptanceRequestOut"];
export type NotificationList = S["NotificationList"];
export type Vulnerability = S["Vulnerability"];
export type SearchResult = S["SearchResult"];
export type Product = S["ProductOut"];
export type BreakdownRow = S["BreakdownRow"];
export type ReportSchedule = S["ScheduleOut"];
export type FindingDetail = S["FindingDetail"];

export type Summary = S["Summary"];
export type Trends = S["Trends"];
export type TopAsset = S["TopAsset"];
export type TopCwe = S["TopCwe"];
export type TopPackage = S["TopPackage"];
export type ApiToken = S["TokenOut"];
export type Meta = S["Meta"];
export type AuditEntry = S["AuditOut"];
export type Job = S["JobOut"];
export type JobStats = S["JobStats"];
export type ScanDiff = S["ScanDiff"];
export type SavedView = S["SavedViewOut"];
export type SlaMatrix = S["SlaMatrix"];
export type TagCount = S["TagCount"];
export type GateResult = S["GateResult"];
export type GateViolation = S["GateViolation"];
export type GatePolicy = S["GatePolicyOut"];
export type GateConditions = S["GateConditions"];
export type PreviewResult = S["PreviewResult"];
export type TriageRule = S["TriageRuleOut"];
export type RuleMatch = S["RuleMatch"];
export type RuleAction = S["RuleAction"];
export type TriagePreview = S["TriagePreviewOut"];
export type Webhook = S["WebhookOut"];
export type WebhookCreated = S["WebhookCreated"];
export type WebhookDelivery = S["DeliveryOut"];
export type Integration = S["IntegrationOut"];
export type FindingLink = S["FindingLinkOut"];
export type IntegrationCheck = S["IntegrationCheck"];
export type ComponentUse = S["ComponentUse"];
export type LicenceCount = S["LicenceCount"];
export type LicensePolicy = S["LicensePolicyOut"];
export type LicenceRule = S["LicenceRule"];
export type MfaChallenge = S["MfaChallenge"];
export type Team = S["TeamOut"];
export type Compliance = S["Compliance"];
export type Coverage = S["Coverage"];

export type FindingUpdate = paths["/api/v1/findings/{finding_id}"]["patch"]["requestBody"]["content"]["application/json"];
export type BulkChange = Omit<paths["/api/v1/findings/bulk"]["post"]["requestBody"]["content"]["application/json"], "ids">;
