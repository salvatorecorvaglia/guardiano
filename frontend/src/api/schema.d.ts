/* biome-ignore-all lint: Generated API declarations. */
/** Generated from openapi.json by pnpm gen:api. Do not edit. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "open" | "in_progress" | "false_positive" | "risk_accepted" | "resolved";
export type ScanType = "sast" | "sca" | "iac" | "dast";
export type Environment = "production" | "staging" | "development" | "test";
export type Criticality = "low" | "medium" | "high" | "critical";
export type AssetType = "repository" | "application" | "service" | "container";
export type EventType =
  | "created"
  | "seen_again"
  | "status_changed"
  | "reopened"
  | "auto_resolved"
  | "no_longer_reported"
  | "assigned"
  | "comment"
  | "rule_applied"
  | "tags_changed"
  | "due_date_changed"
  | "severity_changed"
  | "acceptance_requested"
  | "acceptance_rejected";
export type Role = "admin" | "manager" | "analyst" | "viewer";
export type TokenScope = "ingest" | "read" | "triage";
export type Input_Environment = "production" | "staging" | "development" | "test";
export type Input_Criticality = "low" | "medium" | "high" | "critical";
export type Input_AssetType = "repository" | "application" | "service" | "container";
export type Input_Severity = "critical" | "high" | "medium" | "low" | "info";
export type Input_Status = "open" | "in_progress" | "false_positive" | "risk_accepted" | "resolved";
export type Input_TokenScope = "ingest" | "read" | "triage";
export type Input_ScanType = "sast" | "sca" | "iac" | "dast";
export type Input_Role = "admin" | "manager" | "analyst" | "viewer";

export interface ApiContract {
  components: {
    schemas: {
      AcceptanceDecision: AcceptanceDecision;
      AcceptanceRequestCreate: AcceptanceRequestCreate;
      AcceptanceRequestOut: AcceptanceRequestOut;
      AffectedFinding: AffectedFinding;
      AssetCreate: AssetCreate;
      AssetRef: AssetRef;
      AssetSummary: AssetSummary;
      AssetType: AssetType;
      AssetUpdate: AssetUpdate;
      AuditOut: AuditOut;
      Body_import_vex_api_v1_assets__asset_id__vex_post: BodyImportVexApiV1Assets_AssetId_VexPost;
      Body_upload_scan_api_v1_scans_post: BodyUploadScanApiV1ScansPost;
      BreakdownRow: BreakdownRow;
      BulkChange: BulkChange;
      BulkResult: BulkResult;
      BulkUpdate: BulkUpdate;
      ChangePassword: ChangePassword;
      CommentCreate: CommentCreate;
      Compliance: Compliance;
      ComponentOut: ComponentOut;
      ComponentUse: ComponentUse;
      Coverage: Coverage;
      Criticality: Criticality;
      DeliveryOut: DeliveryOut;
      Environment: Environment;
      EventType: EventType;
      FindingDetail: FindingDetail;
      FindingEventOut: FindingEventOut;
      FindingLinkOut: FindingLinkOut;
      FindingOut: FindingOut;
      FindingUpdate: FindingUpdate;
      FlowPoint: FlowPoint;
      ForgotPassword: ForgotPassword;
      GateConditions: GateConditions;
      GatePolicyOut: GatePolicyOut;
      GatePolicyUpsert: GatePolicyUpsert;
      GateResult: GateResult;
      GateViolation: GateViolation;
      HTTPValidationError: HTTPValidationError;
      IntegrationCheck: IntegrationCheck;
      IntegrationCreate: IntegrationCreate;
      IntegrationOut: IntegrationOut;
      IntegrationUpdate: IntegrationUpdate;
      InventoryStats: InventoryStats;
      JobOut: JobOut;
      JobStats: JobStats;
      LicenceCount: LicenceCount;
      LicenceRule: LicenceRule;
      LicensePolicyOut: LicensePolicyOut;
      LicensePolicyUpdate: LicensePolicyUpdate;
      LoginRequest: LoginRequest;
      LoginResponse: LoginResponse;
      MarkRead: MarkRead;
      Meta: Meta;
      MfaChallenge: MfaChallenge;
      MfaCode: MfaCode;
      MfaDisable: MfaDisable;
      MfaEnabled: MfaEnabled;
      MfaEnrollment: MfaEnrollment;
      MfaSetup: MfaSetup;
      MfaStatus: MfaStatus;
      MfaVerify: MfaVerify;
      MttrPoint: MttrPoint;
      NotificationList: NotificationList;
      NotificationOut: NotificationOut;
      NotificationPrefs: NotificationPrefs;
      NotificationPrefsUpdate: NotificationPrefsUpdate;
      OpenPoint: OpenPoint;
      Owasp: Owasp;
      OwaspCategory: OwaspCategory;
      PackageHit: PackageHit;
      Page_AssetSummary_: Page_AssetSummary_;
      Page_AuditOut_: Page_AuditOut_;
      Page_ComponentOut_: Page_ComponentOut_;
      Page_ComponentUse_: Page_ComponentUse_;
      Page_DeliveryOut_: Page_DeliveryOut_;
      Page_FindingEventOut_: Page_FindingEventOut_;
      Page_FindingOut_: Page_FindingOut_;
      Page_JobOut_: Page_JobOut_;
      Page_ScanOut_: Page_ScanOut_;
      PreviewCounts: PreviewCounts;
      PreviewResult: PreviewResult;
      ProductBody: ProductBody;
      ProductOut: ProductOut;
      ProductUpdate: ProductUpdate;
      Reference: Reference;
      ResetPassword: ResetPassword;
      Role: Role;
      RuleAction: RuleAction;
      RuleMatch: RuleMatch;
      SavedViewCreate: SavedViewCreate;
      SavedViewOut: SavedViewOut;
      SavedViewUpdate: SavedViewUpdate;
      ScanDiff: ScanDiff;
      ScanOut: ScanOut;
      ScanType: ScanType;
      ScheduleBody: ScheduleBody;
      ScheduleOut: ScheduleOut;
      SearchResult: SearchResult;
      Severity: Severity;
      SeverityCounts: SeverityCounts;
      SeverityDays: SeverityDays;
      ShippedComponent: ShippedComponent;
      SlaMatrix: SlaMatrix;
      SlaPerformance: SlaPerformance;
      SlaSeverity: SlaSeverity;
      SlaUpdate: SlaUpdate;
      Status: Status;
      StatusCounts: StatusCounts;
      Summary: Summary;
      TagCount: TagCount;
      TeamCreate: TeamCreate;
      TeamMembers: TeamMembers;
      TeamOut: TeamOut;
      TeamUpdate: TeamUpdate;
      TicketCreate: TicketCreate;
      TokenCreate: TokenCreate;
      TokenCreated: TokenCreated;
      TokenOut: TokenOut;
      TokenScope: TokenScope;
      TopAsset: TopAsset;
      TopCwe: TopCwe;
      TopPackage: TopPackage;
      TopWeakness: TopWeakness;
      Trends: Trends;
      TriageApplyOut: TriageApplyOut;
      TriagePreviewOut: TriagePreviewOut;
      TriagePreviewRequest: TriagePreviewRequest;
      TriageRuleCreate: TriageRuleCreate;
      TriageRuleOut: TriageRuleOut;
      TriageRuleUpdate: TriageRuleUpdate;
      TypeCounts: TypeCounts;
      UncoveredAsset: UncoveredAsset;
      UserBrief: UserBrief;
      UserCreate: UserCreate;
      UserOut: UserOut;
      UserUpdate: UserUpdate;
      ValidationError: ValidationError;
      VexImportResult: VexImportResult;
      Vulnerability: Vulnerability;
      WebhookCreate: WebhookCreate;
      WebhookCreated: WebhookCreated;
      WebhookOut: WebhookOut;
      WebhookUpdate: WebhookUpdate;
    };
  };
  paths: {
    "/api/v1/acceptance-requests": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListRequestsApiV1AcceptanceRequestsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/acceptance-requests/{request_id}/approve": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationApproveApiV1AcceptanceRequests_RequestId_ApprovePost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/acceptance-requests/{request_id}/reject": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationRejectApiV1AcceptanceRequests_RequestId_RejectPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/admin/audit": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListAuditApiV1AdminAuditGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/admin/jobs": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListJobsApiV1AdminJobsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/admin/jobs/stats": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationJobStatsApiV1AdminJobsStatsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/admin/jobs/{job_id}/retry": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationRetryJobApiV1AdminJobs_JobId_RetryPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/breakdown": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationBreakdownApiV1AnalyticsBreakdownGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/compliance": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationComplianceApiV1AnalyticsComplianceGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/coverage": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationCoverageApiV1AnalyticsCoverageGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/summary": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationSummaryApiV1AnalyticsSummaryGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/top": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationTopApiV1AnalyticsTopGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/analytics/trends": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationTrendsApiV1AnalyticsTrendsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/assets": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListAssetsApiV1AssetsGet;
      put?: never;
      post: OperationCreateAssetApiV1AssetsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/assets/options": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationAssetOptionsApiV1AssetsOptionsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/assets/{asset_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetAssetApiV1Assets_AssetId_Get;
      put?: never;
      post?: never;
      delete: OperationDeleteAssetApiV1Assets_AssetId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateAssetApiV1Assets_AssetId_Patch;
      trace?: never;
    };
    "/api/v1/assets/{asset_id}/components": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationAssetComponentsApiV1Assets_AssetId_ComponentsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/assets/{asset_id}/sbom": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationAssetSbomApiV1Assets_AssetId_SbomGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/assets/{asset_id}/vex": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationAssetVexApiV1Assets_AssetId_VexGet;
      put?: never;
      post: OperationImportVexApiV1Assets_AssetId_VexPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/change-password": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationChangePasswordApiV1AuthChangePasswordPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/forgot-password": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationForgotPasswordApiV1AuthForgotPasswordPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/login": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationLoginApiV1AuthLoginPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/login/mfa": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationLoginMfaApiV1AuthLoginMfaPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/logout": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationLogoutApiV1AuthLogoutPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/logout-all": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationLogoutAllApiV1AuthLogoutAllPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/me": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationMeApiV1AuthMeGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/mfa": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationMfaStatusApiV1AuthMfaGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/mfa/disable": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationMfaDisableApiV1AuthMfaDisablePost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/mfa/enable": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationMfaEnableApiV1AuthMfaEnablePost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/mfa/recovery-codes": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationMfaNewRecoveryCodesApiV1AuthMfaRecoveryCodesPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/mfa/setup": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationMfaSetupApiV1AuthMfaSetupPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/preferences": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetPreferencesApiV1AuthPreferencesGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch: OperationUpdatePreferencesApiV1AuthPreferencesPatch;
      trace?: never;
    };
    "/api/v1/auth/refresh": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationRefreshApiV1AuthRefreshPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/auth/reset-password": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationResetPasswordApiV1AuthResetPasswordPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/components": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListComponentsApiV1ComponentsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/components/license-policy": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetLicensePolicyApiV1ComponentsLicensePolicyGet;
      put: OperationPutLicensePolicyApiV1ComponentsLicensePolicyPut;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/components/licenses": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListLicensesApiV1ComponentsLicensesGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/components/stats": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationStatsApiV1ComponentsStatsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListFindingsApiV1FindingsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/bulk": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationBulkUpdateApiV1FindingsBulkPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/bulk/matching": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationBulkUpdateMatchingApiV1FindingsBulkMatchingPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/export.csv": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationExportCsvApiV1FindingsExportCsvGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/export.json": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationExportJsonApiV1FindingsExportJsonGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/export.sarif": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationExportSarifApiV1FindingsExportSarifGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/tags": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListTagsApiV1FindingsTagsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetFindingApiV1Findings_FindingId_Get;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch: OperationUpdateFindingApiV1Findings_FindingId_Patch;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/acceptance-requests": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationCreateRequestApiV1Findings_FindingId_AcceptanceRequestsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/comments": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationAddCommentApiV1Findings_FindingId_CommentsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/events": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationFindingEventsApiV1Findings_FindingId_EventsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/ticket": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationCreateTicketApiV1Findings_FindingId_TicketPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/ticket/{link_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationUnlinkTicketApiV1Findings_FindingId_Ticket_LinkId_Delete;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/findings/{finding_id}/trackers": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListTrackersApiV1Findings_FindingId_TrackersGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/gate-policies": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListPoliciesApiV1GatePoliciesGet;
      put: OperationUpsertPolicyApiV1GatePoliciesPut;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/gate-policies/{policy_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeletePolicyApiV1GatePolicies_PolicyId_Delete;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/integrations": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListIntegrationsApiV1IntegrationsGet;
      put?: never;
      post: OperationCreateIntegrationApiV1IntegrationsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/integrations/{integration_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteIntegrationApiV1Integrations_IntegrationId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateIntegrationApiV1Integrations_IntegrationId_Patch;
      trace?: never;
    };
    "/api/v1/integrations/{integration_id}/check": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationCheckIntegrationApiV1Integrations_IntegrationId_CheckPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/meta": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationMetaApiV1MetaGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/notifications": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListNotificationsApiV1NotificationsGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/notifications/read": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationMarkReadApiV1NotificationsReadPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/products": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListProductsApiV1ProductsGet;
      put?: never;
      post: OperationCreateProductApiV1ProductsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/products/{product_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteProductApiV1Products_ProductId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateProductApiV1Products_ProductId_Patch;
      trace?: never;
    };
    "/api/v1/report-schedules": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListSchedulesApiV1ReportSchedulesGet;
      put?: never;
      post: OperationCreateScheduleApiV1ReportSchedulesPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/report-schedules/{schedule_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put: OperationReplaceScheduleApiV1ReportSchedules_ScheduleId_Put;
      post?: never;
      delete: OperationDeleteScheduleApiV1ReportSchedules_ScheduleId_Delete;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/report-schedules/{schedule_id}/send": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationSendNowApiV1ReportSchedules_ScheduleId_SendPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/scans": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListScansApiV1ScansGet;
      put?: never;
      post: OperationUploadScanApiV1ScansPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/scans/{scan_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetScanApiV1Scans_ScanId_Get;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/scans/{scan_id}/diff": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationScanDiffApiV1Scans_ScanId_DiffGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/search": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationSearchApiV1SearchGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/sla": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetSlaApiV1SlaGet;
      put: OperationPutSlaApiV1SlaPut;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/teams": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListTeamsApiV1TeamsGet;
      put?: never;
      post: OperationCreateTeamApiV1TeamsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/teams/{team_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteTeamApiV1Teams_TeamId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateTeamApiV1Teams_TeamId_Patch;
      trace?: never;
    };
    "/api/v1/teams/{team_id}/members": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put: OperationSetMembersApiV1Teams_TeamId_MembersPut;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/tokens": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListTokensApiV1TokensGet;
      put?: never;
      post: OperationCreateTokenApiV1TokensPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/tokens/{token_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationRevokeTokenApiV1Tokens_TokenId_Delete;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/triage-rules": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListRulesApiV1TriageRulesGet;
      put?: never;
      post: OperationCreateRuleApiV1TriageRulesPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/triage-rules/preview": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationPreviewApiV1TriageRulesPreviewPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/triage-rules/{rule_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteRuleApiV1TriageRules_RuleId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateRuleApiV1TriageRules_RuleId_Patch;
      trace?: never;
    };
    "/api/v1/triage-rules/{rule_id}/apply": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationApplyToExistingApiV1TriageRules_RuleId_ApplyPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/users": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListUsersApiV1UsersGet;
      put?: never;
      post: OperationCreateUserApiV1UsersPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/users/directory": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationDirectoryApiV1UsersDirectoryGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/users/{user_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteUserApiV1Users_UserId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateUserApiV1Users_UserId_Patch;
      trace?: never;
    };
    "/api/v1/views": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListViewsApiV1ViewsGet;
      put?: never;
      post: OperationCreateViewApiV1ViewsPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/views/{view_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteViewApiV1Views_ViewId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateViewApiV1Views_ViewId_Patch;
      trace?: never;
    };
    "/api/v1/vulnerabilities/{vuln_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationGetVulnerabilityApiV1Vulnerabilities_VulnId_Get;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/webhooks": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListWebhooksApiV1WebhooksGet;
      put?: never;
      post: OperationCreateWebhookApiV1WebhooksPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/webhooks/{webhook_id}": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post?: never;
      delete: OperationDeleteWebhookApiV1Webhooks_WebhookId_Delete;
      options?: never;
      head?: never;
      patch: OperationUpdateWebhookApiV1Webhooks_WebhookId_Patch;
      trace?: never;
    };
    "/api/v1/webhooks/{webhook_id}/deliveries": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationListDeliveriesApiV1Webhooks_WebhookId_DeliveriesGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/webhooks/{webhook_id}/rotate-secret": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationRotateSecretApiV1Webhooks_WebhookId_RotateSecretPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/api/v1/webhooks/{webhook_id}/test": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get?: never;
      put?: never;
      post: OperationSendTestApiV1Webhooks_WebhookId_TestPost;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/healthz": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationHealthzHealthzGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
    "/readyz": {
      parameters: {
        query?: never;
        header?: never;
        path?: never;
        cookie?: never;
      };
      get: OperationReadyzReadyzGet;
      put?: never;
      post?: never;
      delete?: never;
      options?: never;
      head?: never;
      patch?: never;
      trace?: never;
    };
  };
  operations: {
    list_requests_api_v1_acceptance_requests_get: OperationListRequestsApiV1AcceptanceRequestsGet;
    approve_api_v1_acceptance_requests__request_id__approve_post: OperationApproveApiV1AcceptanceRequests_RequestId_ApprovePost;
    reject_api_v1_acceptance_requests__request_id__reject_post: OperationRejectApiV1AcceptanceRequests_RequestId_RejectPost;
    list_audit_api_v1_admin_audit_get: OperationListAuditApiV1AdminAuditGet;
    list_jobs_api_v1_admin_jobs_get: OperationListJobsApiV1AdminJobsGet;
    job_stats_api_v1_admin_jobs_stats_get: OperationJobStatsApiV1AdminJobsStatsGet;
    retry_job_api_v1_admin_jobs__job_id__retry_post: OperationRetryJobApiV1AdminJobs_JobId_RetryPost;
    breakdown_api_v1_analytics_breakdown_get: OperationBreakdownApiV1AnalyticsBreakdownGet;
    compliance_api_v1_analytics_compliance_get: OperationComplianceApiV1AnalyticsComplianceGet;
    coverage_api_v1_analytics_coverage_get: OperationCoverageApiV1AnalyticsCoverageGet;
    summary_api_v1_analytics_summary_get: OperationSummaryApiV1AnalyticsSummaryGet;
    top_api_v1_analytics_top_get: OperationTopApiV1AnalyticsTopGet;
    trends_api_v1_analytics_trends_get: OperationTrendsApiV1AnalyticsTrendsGet;
    list_assets_api_v1_assets_get: OperationListAssetsApiV1AssetsGet;
    create_asset_api_v1_assets_post: OperationCreateAssetApiV1AssetsPost;
    asset_options_api_v1_assets_options_get: OperationAssetOptionsApiV1AssetsOptionsGet;
    get_asset_api_v1_assets__asset_id__get: OperationGetAssetApiV1Assets_AssetId_Get;
    delete_asset_api_v1_assets__asset_id__delete: OperationDeleteAssetApiV1Assets_AssetId_Delete;
    update_asset_api_v1_assets__asset_id__patch: OperationUpdateAssetApiV1Assets_AssetId_Patch;
    asset_components_api_v1_assets__asset_id__components_get: OperationAssetComponentsApiV1Assets_AssetId_ComponentsGet;
    asset_sbom_api_v1_assets__asset_id__sbom_get: OperationAssetSbomApiV1Assets_AssetId_SbomGet;
    asset_vex_api_v1_assets__asset_id__vex_get: OperationAssetVexApiV1Assets_AssetId_VexGet;
    import_vex_api_v1_assets__asset_id__vex_post: OperationImportVexApiV1Assets_AssetId_VexPost;
    change_password_api_v1_auth_change_password_post: OperationChangePasswordApiV1AuthChangePasswordPost;
    forgot_password_api_v1_auth_forgot_password_post: OperationForgotPasswordApiV1AuthForgotPasswordPost;
    login_api_v1_auth_login_post: OperationLoginApiV1AuthLoginPost;
    login_mfa_api_v1_auth_login_mfa_post: OperationLoginMfaApiV1AuthLoginMfaPost;
    logout_api_v1_auth_logout_post: OperationLogoutApiV1AuthLogoutPost;
    logout_all_api_v1_auth_logout_all_post: OperationLogoutAllApiV1AuthLogoutAllPost;
    me_api_v1_auth_me_get: OperationMeApiV1AuthMeGet;
    mfa_status_api_v1_auth_mfa_get: OperationMfaStatusApiV1AuthMfaGet;
    mfa_disable_api_v1_auth_mfa_disable_post: OperationMfaDisableApiV1AuthMfaDisablePost;
    mfa_enable_api_v1_auth_mfa_enable_post: OperationMfaEnableApiV1AuthMfaEnablePost;
    mfa_new_recovery_codes_api_v1_auth_mfa_recovery_codes_post: OperationMfaNewRecoveryCodesApiV1AuthMfaRecoveryCodesPost;
    mfa_setup_api_v1_auth_mfa_setup_post: OperationMfaSetupApiV1AuthMfaSetupPost;
    get_preferences_api_v1_auth_preferences_get: OperationGetPreferencesApiV1AuthPreferencesGet;
    update_preferences_api_v1_auth_preferences_patch: OperationUpdatePreferencesApiV1AuthPreferencesPatch;
    refresh_api_v1_auth_refresh_post: OperationRefreshApiV1AuthRefreshPost;
    reset_password_api_v1_auth_reset_password_post: OperationResetPasswordApiV1AuthResetPasswordPost;
    list_components_api_v1_components_get: OperationListComponentsApiV1ComponentsGet;
    get_license_policy_api_v1_components_license_policy_get: OperationGetLicensePolicyApiV1ComponentsLicensePolicyGet;
    put_license_policy_api_v1_components_license_policy_put: OperationPutLicensePolicyApiV1ComponentsLicensePolicyPut;
    list_licenses_api_v1_components_licenses_get: OperationListLicensesApiV1ComponentsLicensesGet;
    stats_api_v1_components_stats_get: OperationStatsApiV1ComponentsStatsGet;
    list_findings_api_v1_findings_get: OperationListFindingsApiV1FindingsGet;
    bulk_update_api_v1_findings_bulk_post: OperationBulkUpdateApiV1FindingsBulkPost;
    bulk_update_matching_api_v1_findings_bulk_matching_post: OperationBulkUpdateMatchingApiV1FindingsBulkMatchingPost;
    export_csv_api_v1_findings_export_csv_get: OperationExportCsvApiV1FindingsExportCsvGet;
    export_json_api_v1_findings_export_json_get: OperationExportJsonApiV1FindingsExportJsonGet;
    export_sarif_api_v1_findings_export_sarif_get: OperationExportSarifApiV1FindingsExportSarifGet;
    list_tags_api_v1_findings_tags_get: OperationListTagsApiV1FindingsTagsGet;
    get_finding_api_v1_findings__finding_id__get: OperationGetFindingApiV1Findings_FindingId_Get;
    update_finding_api_v1_findings__finding_id__patch: OperationUpdateFindingApiV1Findings_FindingId_Patch;
    create_request_api_v1_findings__finding_id__acceptance_requests_post: OperationCreateRequestApiV1Findings_FindingId_AcceptanceRequestsPost;
    add_comment_api_v1_findings__finding_id__comments_post: OperationAddCommentApiV1Findings_FindingId_CommentsPost;
    finding_events_api_v1_findings__finding_id__events_get: OperationFindingEventsApiV1Findings_FindingId_EventsGet;
    create_ticket_api_v1_findings__finding_id__ticket_post: OperationCreateTicketApiV1Findings_FindingId_TicketPost;
    unlink_ticket_api_v1_findings__finding_id__ticket__link_id__delete: OperationUnlinkTicketApiV1Findings_FindingId_Ticket_LinkId_Delete;
    list_trackers_api_v1_findings__finding_id__trackers_get: OperationListTrackersApiV1Findings_FindingId_TrackersGet;
    list_policies_api_v1_gate_policies_get: OperationListPoliciesApiV1GatePoliciesGet;
    upsert_policy_api_v1_gate_policies_put: OperationUpsertPolicyApiV1GatePoliciesPut;
    delete_policy_api_v1_gate_policies__policy_id__delete: OperationDeletePolicyApiV1GatePolicies_PolicyId_Delete;
    list_integrations_api_v1_integrations_get: OperationListIntegrationsApiV1IntegrationsGet;
    create_integration_api_v1_integrations_post: OperationCreateIntegrationApiV1IntegrationsPost;
    delete_integration_api_v1_integrations__integration_id__delete: OperationDeleteIntegrationApiV1Integrations_IntegrationId_Delete;
    update_integration_api_v1_integrations__integration_id__patch: OperationUpdateIntegrationApiV1Integrations_IntegrationId_Patch;
    check_integration_api_v1_integrations__integration_id__check_post: OperationCheckIntegrationApiV1Integrations_IntegrationId_CheckPost;
    meta_api_v1_meta_get: OperationMetaApiV1MetaGet;
    list_notifications_api_v1_notifications_get: OperationListNotificationsApiV1NotificationsGet;
    mark_read_api_v1_notifications_read_post: OperationMarkReadApiV1NotificationsReadPost;
    list_products_api_v1_products_get: OperationListProductsApiV1ProductsGet;
    create_product_api_v1_products_post: OperationCreateProductApiV1ProductsPost;
    delete_product_api_v1_products__product_id__delete: OperationDeleteProductApiV1Products_ProductId_Delete;
    update_product_api_v1_products__product_id__patch: OperationUpdateProductApiV1Products_ProductId_Patch;
    list_schedules_api_v1_report_schedules_get: OperationListSchedulesApiV1ReportSchedulesGet;
    create_schedule_api_v1_report_schedules_post: OperationCreateScheduleApiV1ReportSchedulesPost;
    replace_schedule_api_v1_report_schedules__schedule_id__put: OperationReplaceScheduleApiV1ReportSchedules_ScheduleId_Put;
    delete_schedule_api_v1_report_schedules__schedule_id__delete: OperationDeleteScheduleApiV1ReportSchedules_ScheduleId_Delete;
    send_now_api_v1_report_schedules__schedule_id__send_post: OperationSendNowApiV1ReportSchedules_ScheduleId_SendPost;
    list_scans_api_v1_scans_get: OperationListScansApiV1ScansGet;
    upload_scan_api_v1_scans_post: OperationUploadScanApiV1ScansPost;
    get_scan_api_v1_scans__scan_id__get: OperationGetScanApiV1Scans_ScanId_Get;
    scan_diff_api_v1_scans__scan_id__diff_get: OperationScanDiffApiV1Scans_ScanId_DiffGet;
    search_api_v1_search_get: OperationSearchApiV1SearchGet;
    get_sla_api_v1_sla_get: OperationGetSlaApiV1SlaGet;
    put_sla_api_v1_sla_put: OperationPutSlaApiV1SlaPut;
    list_teams_api_v1_teams_get: OperationListTeamsApiV1TeamsGet;
    create_team_api_v1_teams_post: OperationCreateTeamApiV1TeamsPost;
    delete_team_api_v1_teams__team_id__delete: OperationDeleteTeamApiV1Teams_TeamId_Delete;
    update_team_api_v1_teams__team_id__patch: OperationUpdateTeamApiV1Teams_TeamId_Patch;
    set_members_api_v1_teams__team_id__members_put: OperationSetMembersApiV1Teams_TeamId_MembersPut;
    list_tokens_api_v1_tokens_get: OperationListTokensApiV1TokensGet;
    create_token_api_v1_tokens_post: OperationCreateTokenApiV1TokensPost;
    revoke_token_api_v1_tokens__token_id__delete: OperationRevokeTokenApiV1Tokens_TokenId_Delete;
    list_rules_api_v1_triage_rules_get: OperationListRulesApiV1TriageRulesGet;
    create_rule_api_v1_triage_rules_post: OperationCreateRuleApiV1TriageRulesPost;
    preview_api_v1_triage_rules_preview_post: OperationPreviewApiV1TriageRulesPreviewPost;
    delete_rule_api_v1_triage_rules__rule_id__delete: OperationDeleteRuleApiV1TriageRules_RuleId_Delete;
    update_rule_api_v1_triage_rules__rule_id__patch: OperationUpdateRuleApiV1TriageRules_RuleId_Patch;
    apply_to_existing_api_v1_triage_rules__rule_id__apply_post: OperationApplyToExistingApiV1TriageRules_RuleId_ApplyPost;
    list_users_api_v1_users_get: OperationListUsersApiV1UsersGet;
    create_user_api_v1_users_post: OperationCreateUserApiV1UsersPost;
    directory_api_v1_users_directory_get: OperationDirectoryApiV1UsersDirectoryGet;
    delete_user_api_v1_users__user_id__delete: OperationDeleteUserApiV1Users_UserId_Delete;
    update_user_api_v1_users__user_id__patch: OperationUpdateUserApiV1Users_UserId_Patch;
    list_views_api_v1_views_get: OperationListViewsApiV1ViewsGet;
    create_view_api_v1_views_post: OperationCreateViewApiV1ViewsPost;
    delete_view_api_v1_views__view_id__delete: OperationDeleteViewApiV1Views_ViewId_Delete;
    update_view_api_v1_views__view_id__patch: OperationUpdateViewApiV1Views_ViewId_Patch;
    get_vulnerability_api_v1_vulnerabilities__vuln_id__get: OperationGetVulnerabilityApiV1Vulnerabilities_VulnId_Get;
    list_webhooks_api_v1_webhooks_get: OperationListWebhooksApiV1WebhooksGet;
    create_webhook_api_v1_webhooks_post: OperationCreateWebhookApiV1WebhooksPost;
    delete_webhook_api_v1_webhooks__webhook_id__delete: OperationDeleteWebhookApiV1Webhooks_WebhookId_Delete;
    update_webhook_api_v1_webhooks__webhook_id__patch: OperationUpdateWebhookApiV1Webhooks_WebhookId_Patch;
    list_deliveries_api_v1_webhooks__webhook_id__deliveries_get: OperationListDeliveriesApiV1Webhooks_WebhookId_DeliveriesGet;
    rotate_secret_api_v1_webhooks__webhook_id__rotate_secret_post: OperationRotateSecretApiV1Webhooks_WebhookId_RotateSecretPost;
    send_test_api_v1_webhooks__webhook_id__test_post: OperationSendTestApiV1Webhooks_WebhookId_TestPost;
    healthz_healthz_get: OperationHealthzHealthzGet;
    readyz_readyz_get: OperationReadyzReadyzGet;
  };
}
export interface AcceptanceDecision {
  note?: string | null;
}
export interface AcceptanceRequestCreate {
  justification: string;
  /**
   * When the acceptance should end; may be required by policy
   */
  until?: string | null;
}
export interface AcceptanceRequestOut {
  asset: AssetRef;
  created_at: string;
  decided_at: string | null;
  decided_by: UserBrief | null;
  decision_note: string | null;
  finding_id: number;
  finding_title: string;
  id: number;
  justification: string;
  requested_by: UserBrief | null;
  severity: Severity;
  state: "pending" | "approved" | "rejected";
  until: string | null;
}
export interface AssetRef {
  id: number;
  name: string;
}
export interface UserBrief {
  email: string;
  full_name: string;
  id: number;
}
export interface AffectedFinding {
  asset: AssetRef;
  assignee: UserBrief | null;
  finding_id: number;
  first_seen_at: string;
  fixed_version: string | null;
  package_name: string | null;
  package_version: string | null;
  severity: Severity;
  status: Status;
  title: string;
  type: ScanType;
  url: string | null;
}
export interface AssetCreate {
  criticality: "low" | "medium" | "high" | "critical";
  /**
   * New findings are assigned to this user
   */
  default_assignee_id?: number | null;
  /**
   * Scans of other branches are ingested as previews and never change the inventory
   */
  default_branch?: string | null;
  description: string;
  environment?: Environment | null;
  name: string;
  owner?: string | null;
  /**
   * The product this asset is part of
   */
  product_id?: number | null;
  repo_url?: string | null;
  /**
   * @maxItems 30
   */
  tags?: string[];
  /**
   * Restricts the asset to this team's members; null means everyone can see it
   */
  team_id?: number | null;
  type: "repository" | "application" | "service" | "container";
}
export interface AssetSummary {
  created_at: string;
  criticality: Criticality;
  default_assignee_id?: number | null;
  default_branch?: string | null;
  description: string;
  environment?: Environment | null;
  id: number;
  last_scan_at: string | null;
  name: string;
  open_counts: SeverityCounts;
  open_total: number;
  owner: string | null;
  product_id?: number | null;
  repo_url: string | null;
  risk_score: number;
  tags: string[];
  team_id?: number | null;
  type: AssetType;
}
export interface SeverityCounts {
  critical: number;
  high: number;
  info: number;
  low: number;
  medium: number;
}
export interface AssetUpdate {
  criticality?: Criticality | null;
  default_assignee_id?: number | null;
  default_branch?: string | null;
  description?: string | null;
  environment?: Environment | null;
  name?: string | null;
  owner?: string | null;
  product_id?: number | null;
  repo_url?: string | null;
  tags?: string[] | null;
  team_id?: number | null;
  type?: AssetType | null;
}
export interface AuditOut {
  action: string;
  actor_email: string | null;
  actor_id: number | null;
  changes: {
    [k: string]: unknown;
  };
  created_at: string;
  id: number;
  ip: string | null;
  target_id: number | null;
  target_label: string | null;
  target_type: string | null;
}
export interface BodyImportVexApiV1Assets_AssetId_VexPost {
  /**
   * An OpenVEX or CycloneDX VEX document
   */
  file: string;
}
export interface BodyUploadScanApiV1ScansPost {
  /**
   * Let close_missing act on a report with no findings (skipped by default)
   */
  allow_empty: boolean;
  asset_id?: number | null;
  /**
   * Created automatically if it does not exist
   */
  asset_name?: string | null;
  branch?: string | null;
  /**
   * Resolve active findings from this tool not present in the report
   */
  close_missing: boolean;
  commit_sha?: string | null;
  /**
   * SARIF, CycloneDX JSON, Trivy JSON, Semgrep JSON or Guardiano JSON
   */
  file: string;
  /**
   * Override auto-detection: sarif, cyclonedx, trivy, semgrep, grype, osv, dependency-check, npm-audit, gitleaks, checkov, kics, zap, nuclei, guardiano
   */
  format?: string | null;
  /**
   * Evaluate the report (and its quality gate) without changing the inventory. Implied when the asset has a default_branch and 'branch' differs from it.
   */
  preview: boolean;
  scan_type?: string | null;
}
export interface BreakdownRow {
  /**
   * Findings with an active risk acceptance
   */
  accepted: number;
  critical_high: number;
  /**
   * Product or team id, environment, or tool name; null for none
   */
  key: string | null;
  label: string;
  /**
   * Median hours from first seen to a person's first action, for findings new in the window
   */
  median_triage_hours: number | null;
  /**
   * Mean days to resolve, over those resolved in the window
   */
  mttr_days: number | null;
  open: number;
  overdue: number;
  /**
   * Resolved within the window
   */
  resolved: number;
  /**
   * By tool: open findings another tool reports too
   */
  shared_open?: number | null;
  /**
   * By tool: open findings only this tool reports
   */
  unique_open?: number | null;
}
/**
 * One change applied to many findings.
 */
export interface BulkChange {
  /**
   * @maxItems 20
   */
  add_tags?: string[];
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  justification?: string | null;
  /**
   * @maxItems 20
   */
  remove_tags?: string[];
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Severity | null;
  severity_reason?: string | null;
  status?: Status | null;
  unassign: boolean;
}
export interface BulkResult {
  updated: number;
}
export interface BulkUpdate {
  /**
   * @maxItems 20
   */
  add_tags?: string[];
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  /**
   * @minItems 1
   * @maxItems 1000
   */
  ids: number[];
  justification?: string | null;
  /**
   * @maxItems 20
   */
  remove_tags?: string[];
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Severity | null;
  severity_reason?: string | null;
  status?: Status | null;
  unassign: boolean;
}
export interface ChangePassword {
  current_password: string;
  new_password: string;
}
export interface CommentCreate {
  text: string;
}
export interface Compliance {
  asset_id?: number | null;
  cwe_top_25: TopWeakness[];
  cwe_top_25_edition: string;
  generated_at: string;
  mttr_trend: MttrPoint[];
  owasp: Owasp;
  sla: SlaPerformance;
}
export interface TopWeakness {
  critical_high: number;
  cwe: string;
  name: string;
  open: number;
  rank: number;
}
export interface MttrPoint {
  days: number;
  period: string;
  resolved: number;
}
export interface Owasp {
  categories: OwaspCategory[];
  edition: string;
  mapped: number;
  open_total: number;
  unmapped: number;
}
export interface OwaspCategory {
  critical_high: number;
  id: string;
  open: number;
  title: string;
}
export interface SlaPerformance {
  by_severity: SlaSeverity[];
  days: number;
  open: number;
  resolved: number;
  resolved_on_time: number;
  resolved_on_time_pct: number | null;
  severity: string;
  within_sla: number;
  within_sla_pct: number | null;
}
export interface SlaSeverity {
  open: number;
  resolved: number;
  resolved_on_time: number;
  resolved_on_time_pct: number | null;
  severity: string;
  within_sla: number;
  within_sla_pct: number | null;
}
/**
 * One package shipped by one asset: the answer to "what is in this service?".
 */
export interface ComponentOut {
  ecosystem: string | null;
  first_seen_at: string;
  id: number;
  last_seen_at: string;
  licence_rule: string;
  licenses: string[];
  name: string;
  purl: string | null;
  version: string | null;
}
/**
 * One package version, and everywhere it is used.
 */
export interface ComponentUse {
  assets: AssetRef[];
  ecosystem: string | null;
  last_seen_at: string;
  licence_rule: string;
  licenses: string[];
  name: string;
  purl: string | null;
  version: string | null;
}
/**
 * How many assets are scanned recently enough. Preview scans do not count.
 */
export interface Coverage {
  assets: number;
  covered: number;
  never_scanned: number;
  /**
   * Scanned, but not within stale_days
   */
  stale: number;
  stale_days: number;
  /**
   * Never-scanned assets first, then the longest-unscanned; at most 200
   */
  uncovered: UncoveredAsset[];
  without_sast: number;
  without_sca: number;
}
export interface UncoveredAsset {
  criticality: string;
  has_sbom: boolean;
  id: number;
  last_sast_at: string | null;
  last_sca_at: string | null;
  last_scan_at: string | null;
  name: string;
}
export interface DeliveryOut {
  attempts: number;
  created_at: string;
  delivered_at: string | null;
  error: string | null;
  event: string;
  id: number;
  payload: {
    [k: string]: unknown;
  };
  status_code: number | null;
}
export interface FindingDetail {
  asset: AssetRef;
  assignee: UserBrief | null;
  closed_at: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  cwe: string[];
  description: string;
  due_at_override?: string | null;
  ecosystem: string | null;
  epss?: number | null;
  epss_percentile?: number | null;
  events: FindingEventOut[];
  events_total: number;
  file_path: string | null;
  first_scan_id: number | null;
  first_seen_at: string;
  fixed_version: string | null;
  http_method?: string | null;
  id: number;
  in_kev: boolean;
  kev_due_date?: string | null;
  kev_ransomware: boolean;
  last_scan_id: number | null;
  last_seen_at: string;
  line_end: number | null;
  line_start: number | null;
  links: FindingLinkOut[];
  occurrence_count: number;
  overdue: boolean;
  package_name: string | null;
  package_version: string | null;
  parameter?: string | null;
  /**
   * Severity weight x exploitability x asset criticality (0-40 with default settings); see services/priority.py
   */
  priority: number;
  purl: string | null;
  references: Reference[];
  remediation: string;
  resource?: string | null;
  risk_accepted_until: string | null;
  rule_id: string | null;
  scanner_severity?: Severity | null;
  severity: Severity;
  severity_override?: Severity | null;
  sla_due_at?: string | null;
  snippet: string | null;
  status: Status;
  status_justification: string | null;
  tags: string[];
  title: string;
  tools: string[];
  type: ScanType;
  url?: string | null;
  vuln_id: string | null;
}
export interface FindingEventOut {
  actor: UserBrief | null;
  comment: string | null;
  created_at: string;
  event: EventType;
  from_status: Status | null;
  id: number;
  scan_id: number | null;
  to_status: Status | null;
}
export interface FindingLinkOut {
  created_at: string;
  created_by: UserBrief | null;
  external_key: string;
  id: number;
  remote_done_at?: string | null;
  remote_status: string | null;
  synced_at: string | null;
  system: string;
  url: string;
}
export interface Reference {
  title?: string | null;
  url?: string | null;
}
export interface FindingOut {
  asset: AssetRef;
  assignee: UserBrief | null;
  closed_at: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  cwe: string[];
  due_at_override?: string | null;
  epss?: number | null;
  epss_percentile?: number | null;
  file_path: string | null;
  first_seen_at: string;
  fixed_version: string | null;
  http_method?: string | null;
  id: number;
  in_kev: boolean;
  kev_due_date?: string | null;
  kev_ransomware: boolean;
  last_seen_at: string;
  line_start: number | null;
  overdue: boolean;
  package_name: string | null;
  package_version: string | null;
  parameter?: string | null;
  /**
   * Severity weight x exploitability x asset criticality (0-40 with default settings); see services/priority.py
   */
  priority: number;
  resource?: string | null;
  rule_id: string | null;
  scanner_severity?: Severity | null;
  severity: Severity;
  severity_override?: Severity | null;
  sla_due_at?: string | null;
  status: Status;
  tags: string[];
  title: string;
  tools: string[];
  type: ScanType;
  url?: string | null;
  vuln_id: string | null;
}
export interface FindingUpdate {
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  justification?: string | null;
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Severity | null;
  severity_reason?: string | null;
  status?: Status | null;
  /**
   * Replaces the finding's tags
   */
  tags?: string[] | null;
  unassign: boolean;
}
export interface FlowPoint {
  closed: number;
  new: number;
  period: string;
}
export interface ForgotPassword {
  email: string;
}
/**
 * All conditions are optional; a policy with none always passes.
 */
export interface GateConditions {
  /**
   * Fail when the report lists a component whose licence the licence policy denies
   */
  fail_on_denied_license: boolean;
  /**
   * Fail when the asset carries an open finding whose CVE is in CISA's Known Exploited Vulnerabilities catalogue
   */
  fail_on_kev: boolean;
  /**
   * Fail when this scan introduces a hard-coded credential (CWE-798, CWE-259 or CWE-321, as Gitleaks and secret scanners report them)
   */
  fail_on_new_secrets: boolean;
  /**
   * Fail when the asset has findings past their SLA
   */
  fail_on_overdue: boolean;
  /**
   * Fail when the scan reopens a resolved finding
   */
  fail_on_reopened: boolean;
  /**
   * Most new findings this scan may introduce, per severity
   */
  max_new?: {
    [k: string]: number;
  };
  /**
   * Fail when this scan introduces a finding with a CVSS score above this
   */
  max_new_cvss?: number | null;
  /**
   * Most active findings the asset may carry, per severity
   */
  max_open?: {
    [k: string]: number;
  };
  /**
   * Fail when the asset carries an open finding whose EPSS probability is above this (0-1). Scores arrive with the daily intel sync, so a CVE first seen today counts from tomorrow
   */
  max_open_epss?: number | null;
}
export interface GatePolicyOut {
  asset: AssetRef | null;
  conditions: GateConditions;
  created_at: string;
  enabled: boolean;
  id: number;
  updated_at: string;
}
export interface GatePolicyUpsert {
  /**
   * null is the global policy, used by assets without one
   */
  asset_id?: number | null;
  conditions?: GateConditions;
  enabled: boolean;
}
export interface GateResult {
  evaluated_at: string;
  passed: boolean;
  policy_id: number;
  policy_scope: "asset" | "global";
  violations: GateViolation[];
}
export interface GateViolation {
  actual: number;
  limit?: number | null;
  message: string;
  rule: string;
  severity?: string | null;
}
export interface HTTPValidationError {
  detail?: ValidationError[];
}
export interface ValidationError {
  ctx?: {};
  input?: unknown;
  loc: (string | number)[];
  msg: string;
  type: string;
}
export interface IntegrationCheck {
  detail: string;
  ok: boolean;
}
export interface IntegrationCreate {
  /**
   * null offers this tracker for every asset
   */
  asset_id?: number | null;
  /**
   * Open a ticket for each new finding whose CVE is in CISA KEV
   */
  auto_ticket_kev: boolean;
  /**
   * Open a ticket for each new finding at or above this severity
   */
  auto_ticket_min_severity?: Severity | null;
  base_url: string;
  /**
   * Resolve a finding when polling finds its ticket closed (needs TRACKER_POLL_HOURS)
   */
  close_resolves_finding: boolean;
  /**
   * Jira: transition that closes
   */
  done_transition?: string | null;
  enabled: boolean;
  /**
   * Jira issue type, e.g. "Bug"
   */
  issue_type?: string | null;
  kind: "jira" | "github" | "gitlab";
  /**
   * @maxItems 20
   */
  labels?: string[];
  name: string;
  /**
   * Jira key, owner/repo, or GitLab path
   */
  project: string;
  /**
   * Jira: transition that reopens
   */
  reopen_transition?: string | null;
  /**
   * Report scan and gate results on commits and pull requests (GitHub/GitLab)
   */
  scm_feedback: boolean;
  /**
   * API token; stored encrypted
   */
  token: string;
  /**
   * Jira account email; blank for a PAT
   */
  username?: string | null;
}
/**
 * The token is never returned.
 */
export interface IntegrationOut {
  asset: AssetRef | null;
  auto_ticket_kev: boolean;
  auto_ticket_min_severity: Severity | null;
  base_url: string;
  close_resolves_finding: boolean;
  created_at: string;
  done_transition: string | null;
  enabled: boolean;
  id: number;
  issue_type: string | null;
  kind: string;
  labels: string[];
  last_error: string | null;
  last_used_at: string | null;
  name: string;
  project: string;
  reopen_transition: string | null;
  scm_feedback: boolean;
  username: string | null;
}
export interface IntegrationUpdate {
  asset_id?: number | null;
  auto_ticket_kev?: boolean | null;
  /**
   * null (when given) turns it off
   */
  auto_ticket_min_severity?: Severity | null;
  base_url?: string | null;
  close_resolves_finding?: boolean | null;
  /**
   * "" removes it
   */
  done_transition?: string | null;
  enabled?: boolean | null;
  issue_type?: string | null;
  labels?: string[] | null;
  name?: string | null;
  project?: string | null;
  /**
   * "" removes it
   */
  reopen_transition?: string | null;
  scm_feedback?: boolean | null;
  /**
   * Replaces the stored token
   */
  token?: string | null;
  username?: string | null;
}
export interface InventoryStats {
  assets: number;
  components: number;
  distinct: number;
  last_seen_at: string | null;
}
export interface JobOut {
  attempts: number;
  created_at: string;
  finished_at: string | null;
  id: number;
  kind: string;
  last_error: string | null;
  locked_at: string | null;
  max_attempts: number;
  payload: {
    [k: string]: unknown;
  };
  run_after: string;
  status: string;
}
export interface JobStats {
  counts: {
    [k: string]: number;
  };
  last_finished_at: string | null;
  oldest_queued_at: string | null;
}
export interface LicenceCount {
  components: number;
  licence: string;
  rule: string;
}
export interface LicenceRule {
  licence: string;
  note?: string | null;
  rule: "allowed" | "denied" | "review";
}
/**
 * The policy, plus what unlisted licences default to.
 */
export interface LicensePolicyOut {
  default: string;
  rules: LicenceRule[];
}
export interface LicensePolicyUpdate {
  /**
   * @maxItems 500
   */
  rules: LicenceRule[];
}
export interface LoginRequest {
  email: string;
  password: string;
}
export interface LoginResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  user: UserOut;
}
export interface UserOut {
  created_at: string;
  email: string;
  full_name: string;
  id: number;
  is_active: boolean;
  last_login_at: string | null;
  mfa_enabled: boolean;
  mfa_enrollment_required: boolean;
  mfa_setup_required: boolean;
  role: Role;
}
export interface MarkRead {
  /**
   * null marks every notification read
   */
  ids?: number[] | null;
}
export interface Meta {
  docs_enabled: boolean;
  email_enabled: boolean;
  formats: string[];
  local_login: boolean;
  max_upload_mb: number;
  name: string;
  oidc_enabled: boolean;
  oidc_label: string;
  sla_days: {
    [k: string]: number;
  };
  version: string;
}
/**
 * Returned instead of a session when the account has a second factor.
 */
export interface MfaChallenge {
  expires_in: number;
  mfa_required: boolean;
  mfa_token: string;
}
export interface MfaCode {
  code: string;
}
export interface MfaDisable {
  code: string;
  password: string;
}
/**
 * The recovery codes are shown once, here.
 */
export interface MfaEnabled {
  recovery_codes: string[];
  session?: LoginResponse | null;
}
export interface MfaEnrollment {
  recovery_codes: string[];
  session: LoginResponse;
}
export interface MfaSetup {
  otpauth_uri: string;
  secret: string;
}
export interface MfaStatus {
  confirmed_at: string | null;
  enabled: boolean;
  recovery_codes_left: number;
  required: boolean;
}
export interface MfaVerify {
  /**
   * A TOTP code or a recovery code
   */
  code: string;
  mfa_token: string;
}
export interface NotificationList {
  items: NotificationOut[];
  unread: number;
}
export interface NotificationOut {
  actor: UserBrief | null;
  created_at: string;
  finding_id: number | null;
  id: number;
  kind: string;
  read_at: string | null;
  text: string;
}
/**
 * Email preferences. Nothing is sent unless the server has SMTP configured.
 */
export interface NotificationPrefs {
  digest_frequency: "off" | "daily" | "weekly";
  notify_on_assignment: boolean;
}
export interface NotificationPrefsUpdate {
  digest_frequency?: ("off" | "daily" | "weekly") | null;
  notify_on_assignment?: boolean | null;
}
export interface OpenPoint {
  critical: number;
  date: string;
  high: number;
  info: number;
  low: number;
  medium: number;
}
export interface PackageHit {
  assets: number;
  ecosystem: string | null;
  name: string;
}
export interface Page_AssetSummary_ {
  items: AssetSummary[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_AuditOut_ {
  items: AuditOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_ComponentOut_ {
  items: ComponentOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_ComponentUse_ {
  items: ComponentUse[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_DeliveryOut_ {
  items: DeliveryOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_FindingEventOut_ {
  items: FindingEventOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_FindingOut_ {
  items: FindingOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_JobOut_ {
  items: JobOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface Page_ScanOut_ {
  items: ScanOut[];
  page: number;
  page_size: number;
  total: number;
}
export interface ScanOut {
  asset: AssetRef;
  auto_resolved_count: number;
  branch: string | null;
  commit_sha: string | null;
  created_at: string;
  duplicate_count: number;
  file_name: string | null;
  format: string;
  gate?: GateResult | null;
  id: number;
  new_count: number;
  preview?: PreviewResult | null;
  reopened_count: number;
  scan_type: ScanType;
  source: "upload" | "api" | "preview";
  tool_name: string;
  tool_version: string | null;
  total_count: number;
  uploaded_by: UserBrief | null;
}
/**
 * What a preview scan would add, had it been ingested.
 */
export interface PreviewResult {
  branch: string | null;
  counts: PreviewCounts;
  default_branch: string | null;
  new: {
    [k: string]: unknown;
  }[];
  truncated: boolean;
}
export interface PreviewCounts {
  known: number;
  new: number;
  new_by_severity: {
    [k: string]: number;
  };
  total: number;
}
export interface ProductBody {
  description: string;
  name: string;
}
/**
 * A product, with totals over the assets of it that you can see.
 */
export interface ProductOut {
  assets: number;
  description: string;
  id: number;
  name: string;
  open_counts?: SeverityCounts;
  open_total: number;
}
export interface ProductUpdate {
  description?: string | null;
  name?: string | null;
}
export interface ResetPassword {
  new_password: string;
  token: string;
}
/**
 * What to do with a matching finding. At least one effect must be given.
 */
export interface RuleAction {
  assignee_id?: number | null;
  justification?: string | null;
  /**
   * Override the scanner's severity
   */
  severity?: Severity | null;
  /**
   * Only false_positive: risk acceptance needs a person and an expiry date
   */
  status?: "false_positive" | null;
  /**
   * @maxItems 20
   */
  tags?: string[];
}
/**
 * Conditions a finding must all satisfy. At least one must be given.
 */
export interface RuleMatch {
  asset_criticality?: Criticality[];
  /**
   * The asset must carry every one of these tags
   *
   * @maxItems 20
   */
  asset_tags?: string[];
  /**
   * Exact CVE id, e.g. "CVE-2021-44228"
   */
  cve?: string | null;
  /**
   * "89" or "CWE-89"
   */
  cwe?: string | null;
  /**
   * e.g. "npm", "pypi", "maven"
   */
  ecosystem?: string | null;
  /**
   * Only CVEs with at least this EPSS
   */
  epss_min?: number | null;
  /**
   * true: only CVEs in CISA's KEV catalogue; false: only CVEs that are not
   */
  kev?: boolean | null;
  package?: string | null;
  /**
   * e.g. "tests/*" or "* /vendor/*"
   */
  path_glob?: string | null;
  rule_id?: string | null;
  severity?: Severity[];
  title_contains?: string | null;
  tool?: string | null;
  type?: ScanType | null;
}
export interface SavedViewCreate {
  name: string;
  /**
   * Findings page query string, e.g. severity=high&status=open
   */
  query: string;
  shared: boolean;
}
export interface SavedViewOut {
  created_at: string;
  id: number;
  name: string;
  query: string;
  shared: boolean;
  updated_at: string;
  user: UserBrief;
}
export interface SavedViewUpdate {
  name?: string | null;
  query?: string | null;
  shared?: boolean | null;
}
/**
 * How a scan's findings compare with an earlier scan of the same asset.
 *
 * List the findings themselves with ``GET /findings?scan_id=&not_in_scan_id=``: ``new`` is
 * ``scan_id=<scan>&not_in_scan_id=<against>`` and ``no_longer_reported`` is the reverse.
 */
export interface ScanDiff {
  against: ScanOut | null;
  new: number;
  no_longer_reported: number;
  scan: ScanOut;
  unchanged: number;
}
export interface ScheduleBody {
  enabled: boolean;
  frequency: "weekly" | "monthly";
  name: string;
  /**
   * Only this product; null for everything the reader sees
   */
  product_id?: number | null;
  /**
   * Guardiano users
   *
   * @minItems 1
   * @maxItems 50
   */
  recipient_ids: number[];
}
export interface ScheduleOut {
  enabled: boolean;
  frequency: string;
  id: number;
  last_sent_at: string | null;
  name: string;
  product_id: number | null;
  recipient_ids: number[];
}
export interface SearchResult {
  assets: AssetRef[];
  findings: FindingOut[];
  packages: PackageHit[];
  vulnerability: string | null;
}
export interface SeverityDays {
  critical?: number | null;
  high?: number | null;
  info?: number | null;
  low?: number | null;
  medium?: number | null;
}
/**
 * An asset whose inventory lists a vulnerable package, with no finding for this vulnerability.
 */
export interface ShippedComponent {
  asset: AssetRef;
  ecosystem: string | null;
  last_seen_at: string;
  name: string;
  same_version: boolean;
  version: string | null;
}
/**
 * Remediation SLA in days, by severity (rows) and asset criticality (columns).
 *
 * ``days[severity]["any"]`` is the effective default for the severity. The other columns hold a
 * criticality-specific override, or ``null`` when that criticality uses the default.
 */
export interface SlaMatrix {
  criticalities: string[];
  days: {
    [k: string]: {
      [k: string]: number | null;
    };
  };
  env_defaults: {
    [k: string]: number;
  };
  severities: string[];
}
/**
 * Replaces every policy. ``null`` (or omission) means inherit: "any" falls back to SLA_*_DAYS.
 */
export interface SlaUpdate {
  days: {
    [k: string]: {
      [k: string]: number | null;
    };
  };
}
export interface StatusCounts {
  false_positive: number;
  in_progress: number;
  open: number;
  resolved: number;
  risk_accepted: number;
}
export interface Summary {
  assets_total: number;
  by_status: StatusCounts;
  known_exploited: number;
  mttr_days: SeverityDays;
  mttr_days_overall: number | null;
  new_last_30d: number;
  open_by_severity: SeverityCounts;
  open_by_type: TypeCounts;
  open_total: number;
  overdue: number;
  resolved_last_30d: number;
  scans_last_30d: number;
}
export interface TypeCounts {
  dast: number;
  iac: number;
  sast: number;
  sca: number;
}
export interface TagCount {
  active: number;
  count: number;
  tag: string;
}
export interface TeamCreate {
  description: string;
  name: string;
}
export interface TeamMembers {
  /**
   * @maxItems 500
   */
  user_ids?: number[];
}
export interface TeamOut {
  asset_count: number;
  description: string;
  id: number;
  member_count: number;
  members?: UserBrief[];
  name: string;
}
export interface TeamUpdate {
  description?: string | null;
  name?: string | null;
}
export interface TicketCreate {
  /**
   * Defaults to the only tracker available
   */
  integration_id?: number | null;
}
export interface TokenCreate {
  expires_in_days: number | null;
  name: string;
  scopes?: TokenScope[];
}
export interface TokenCreated {
  created_at: string;
  expires_at: string | null;
  id: number;
  last_used_at: string | null;
  name: string;
  prefix: string;
  revoked_at: string | null;
  scopes: TokenScope[];
  token: string;
  user: UserBrief;
}
export interface TokenOut {
  created_at: string;
  expires_at: string | null;
  id: number;
  last_used_at: string | null;
  name: string;
  prefix: string;
  revoked_at: string | null;
  scopes: TokenScope[];
  user: UserBrief;
}
export interface TopAsset {
  critical: number;
  criticality: string;
  high: number;
  id: number;
  low: number;
  medium: number;
  name: string;
  open: number;
  risk_score: number;
}
export interface TopCwe {
  count: number;
  cwe: string;
}
export interface TopPackage {
  assets: number;
  count: number;
  critical_high: number;
  ecosystem: string | null;
  package: string;
}
export interface Trends {
  bucket: "day" | "week";
  days: number;
  new_vs_closed: FlowPoint[];
  open_by_severity: OpenPoint[];
  severity_history_complete: boolean;
}
/**
 * Applying a rule to existing findings runs in the background; the audit log records the request.
 */
export interface TriageApplyOut {
  job_id: number;
}
/**
 * A dry run over findings that already exist. Rules themselves only ever act on new findings.
 */
export interface TriagePreviewOut {
  matched: number;
  sample: FindingOut[];
  scanned: number;
  truncated: boolean;
}
export interface TriagePreviewRequest {
  asset_id?: number | null;
  /**
   * How many matching findings to return
   */
  limit: number;
  match: RuleMatch;
}
export interface TriageRuleCreate {
  action?: RuleAction;
  /**
   * null applies the rule to every asset
   */
  asset_id?: number | null;
  enabled: boolean;
  expires_at?: string | null;
  match?: RuleMatch;
  name: string;
  /**
   * Lowest runs first
   */
  priority: number;
}
export interface TriageRuleOut {
  action: RuleAction;
  applied_count: number;
  asset: AssetRef | null;
  created_at: string;
  created_by: UserBrief | null;
  enabled: boolean;
  expires_at: string | null;
  id: number;
  match: RuleMatch;
  name: string;
  priority: number;
  updated_at: string;
}
/**
 * Only the fields given are changed; match and action are replaced wholesale.
 */
export interface TriageRuleUpdate {
  action?: RuleAction | null;
  asset_id?: number | null;
  clear_expiry: boolean;
  enabled?: boolean | null;
  expires_at?: string | null;
  match?: RuleMatch | null;
  name?: string | null;
  priority?: number | null;
}
export interface UserCreate {
  email: string;
  full_name: string;
  password: string;
  role: "admin" | "manager" | "analyst" | "viewer";
}
export interface UserUpdate {
  full_name?: string | null;
  is_active?: boolean | null;
  password?: string | null;
  role?: Role | null;
}
export interface VexImportResult {
  already_closed: number;
  changed: number;
  format: string;
  informational: number;
  statements: number;
  unmatched: string[];
}
/**
 * One vulnerability across every asset you can see: the page to open on an incident morning.
 */
export interface Vulnerability {
  also_ships: ShippedComponent[];
  also_ships_truncated: boolean;
  assets_affected: number;
  by_status: {
    [k: string]: number;
  };
  epss: number | null;
  epss_percentile: number | null;
  findings: AffectedFinding[];
  findings_total: number;
  id: string;
  in_kev: boolean;
  kev_due_date: string | null;
  kev_ransomware: boolean;
  open: number;
  page: number;
  page_size: number;
}
export interface WebhookCreate {
  /**
   * null sends events for every asset
   */
  asset_id?: number | null;
  enabled: boolean;
  /**
   * @minItems 1
   */
  events: (
    | "scan.completed"
    | "gate.failed"
    | "finding.reopened"
    | "finding.status_changed"
    | "finding.assigned"
    | "finding.risk_acceptance_expiring"
    | "finding.kev_added"
    | "sla.breached"
    | "test"
  )[];
  format: "guardiano" | "slack" | "teams";
  /**
   * Ignored by scan.completed, gate.failed and test events
   */
  min_severity: "critical" | "high" | "medium" | "low" | "info";
  name: string;
  url: string;
}
/**
 * The signing secret is returned only here and when it is rotated.
 */
export interface WebhookCreated {
  asset: AssetRef | null;
  created_at: string;
  enabled: boolean;
  events: string[];
  format: string;
  id: number;
  last_delivery_at: string | null;
  last_error: string | null;
  last_status: number | null;
  min_severity: string;
  name: string;
  secret: string;
  url: string;
}
export interface WebhookOut {
  asset: AssetRef | null;
  created_at: string;
  enabled: boolean;
  events: string[];
  format: string;
  id: number;
  last_delivery_at: string | null;
  last_error: string | null;
  last_status: number | null;
  min_severity: string;
  name: string;
  url: string;
}
export interface WebhookUpdate {
  asset_id?: number | null;
  enabled?: boolean | null;
  events?:
    | (
        | "scan.completed"
        | "gate.failed"
        | "finding.reopened"
        | "finding.status_changed"
        | "finding.assigned"
        | "finding.risk_acceptance_expiring"
        | "finding.kev_added"
        | "sla.breached"
        | "test"
      )[]
    | null;
  format?: ("guardiano" | "slack" | "teams") | null;
  min_severity?: Severity | null;
  name?: string | null;
  rotate_secret: boolean;
  url?: string | null;
}
export interface OperationListRequestsApiV1AcceptanceRequestsGet {
  parameters: {
    query?: {
      state?: ("pending" | "approved" | "rejected") | null;
      finding_id?: number | null;
      limit?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AcceptanceRequestOut[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationApproveApiV1AcceptanceRequests_RequestId_ApprovePost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      request_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AcceptanceRequestOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_AcceptanceDecision;
    };
  };
}
export interface Input_AcceptanceDecision {
  note?: string | null;
}
export interface OperationRejectApiV1AcceptanceRequests_RequestId_RejectPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      request_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AcceptanceRequestOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_AcceptanceDecision;
    };
  };
}
export interface OperationListAuditApiV1AdminAuditGet {
  parameters: {
    query?: {
      /**
       * Exact action, or a prefix ending in '.'
       */
      action?: string | null;
      actor_id?: number | null;
      target_type?: string | null;
      target_id?: number | null;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_AuditOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListJobsApiV1AdminJobsGet {
  parameters: {
    query?: {
      status?: string | null;
      kind?: string | null;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_JobOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationJobStatsApiV1AdminJobsStatsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": JobStats;
      };
    };
  };
  requestBody?: never;
}
export interface OperationRetryJobApiV1AdminJobs_JobId_RetryPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      job_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": JobOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationBreakdownApiV1AnalyticsBreakdownGet {
  parameters: {
    query?: {
      by?: "product" | "team" | "environment" | "tool";
      /**
       * Window for resolved, MTTR and time to triage
       */
      days?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": BreakdownRow[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationComplianceApiV1AnalyticsComplianceGet {
  parameters: {
    query?: {
      asset_id?: number | null;
      /**
       * Window for the 'resolved on time' figures
       */
      days?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Compliance;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationCoverageApiV1AnalyticsCoverageGet {
  parameters: {
    query?: {
      /**
       * An asset not scanned for this long is stale
       */
      stale_days?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Coverage;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationSummaryApiV1AnalyticsSummaryGet {
  parameters: {
    query?: {
      asset_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Summary;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationTopApiV1AnalyticsTopGet {
  parameters: {
    query?: {
      by?: "assets" | "cwes" | "packages";
      limit?: number;
      asset_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TopAsset[] | TopCwe[] | TopPackage[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationTrendsApiV1AnalyticsTrendsGet {
  parameters: {
    query?: {
      days?: number;
      asset_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Trends;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListAssetsApiV1AssetsGet {
  parameters: {
    query?: {
      q?: string | null;
      product_id?: number | null;
      environment?: string | null;
      sort?: string;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_AssetSummary_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateAssetApiV1AssetsPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AssetSummary;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_AssetCreate;
    };
  };
}
export interface Input_AssetCreate {
  criticality?: "low" | "medium" | "high" | "critical";
  /**
   * New findings are assigned to this user
   */
  default_assignee_id?: number | null;
  /**
   * Scans of other branches are ingested as previews and never change the inventory
   */
  default_branch?: string | null;
  description?: string;
  environment?: Input_Environment | null;
  name: string;
  owner?: string | null;
  /**
   * The product this asset is part of
   */
  product_id?: number | null;
  repo_url?: string | null;
  /**
   * @maxItems 30
   */
  tags?: string[];
  /**
   * Restricts the asset to this team's members; null means everyone can see it
   */
  team_id?: number | null;
  type?: "repository" | "application" | "service" | "container";
}
export interface OperationAssetOptionsApiV1AssetsOptionsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AssetRef[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationGetAssetApiV1Assets_AssetId_Get {
  parameters: {
    query?: never;
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AssetSummary;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationDeleteAssetApiV1Assets_AssetId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateAssetApiV1Assets_AssetId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AssetSummary;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_AssetUpdate;
    };
  };
}
export interface Input_AssetUpdate {
  criticality?: Input_Criticality | null;
  default_assignee_id?: number | null;
  default_branch?: string | null;
  description?: string | null;
  environment?: Input_Environment | null;
  name?: string | null;
  owner?: string | null;
  product_id?: number | null;
  repo_url?: string | null;
  tags?: string[] | null;
  team_id?: number | null;
  type?: Input_AssetType | null;
}
export interface OperationAssetComponentsApiV1Assets_AssetId_ComponentsGet {
  parameters: {
    query?: {
      /**
       * Name or purl
       */
      q?: string | null;
      ecosystem?: string | null;
      sort?: string;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_ComponentOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationAssetSbomApiV1Assets_AssetId_SbomGet {
  parameters: {
    query?: {
      format?: "cyclonedx" | "spdx";
      /**
       * current: what each tool's latest scan listed; all: every component ever seen
       */
      include?: "current" | "all";
    };
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": unknown;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationAssetVexApiV1Assets_AssetId_VexGet {
  parameters: {
    query?: {
      format?: "openvex" | "cyclonedx";
    };
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": unknown;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationImportVexApiV1Assets_AssetId_VexPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      asset_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": VexImportResult;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "multipart/form-data": Input_BodyImportVexApiV1Assets_AssetId_VexPost;
    };
  };
}
export interface Input_BodyImportVexApiV1Assets_AssetId_VexPost {
  /**
   * An OpenVEX or CycloneDX VEX document
   */
  file: Blob;
}
export interface OperationChangePasswordApiV1AuthChangePasswordPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LoginResponse;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ChangePassword;
    };
  };
}
export interface Input_ChangePassword {
  current_password: string;
  new_password: string;
}
export interface OperationForgotPasswordApiV1AuthForgotPasswordPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ForgotPassword;
    };
  };
}
export interface Input_ForgotPassword {
  email: string;
}
export interface OperationLoginApiV1AuthLoginPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LoginResponse | MfaChallenge;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_LoginRequest;
    };
  };
}
export interface Input_LoginRequest {
  email: string;
  password: string;
}
export interface OperationLoginMfaApiV1AuthLoginMfaPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LoginResponse;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_MfaVerify;
    };
  };
}
export interface Input_MfaVerify {
  /**
   * A TOTP code or a recovery code
   */
  code: string;
  mfa_token: string;
}
export interface OperationLogoutApiV1AuthLogoutPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
  };
  requestBody?: never;
}
export interface OperationLogoutAllApiV1AuthLogoutAllPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
  };
  requestBody?: never;
}
export interface OperationMeApiV1AuthMeGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": UserOut;
      };
    };
  };
  requestBody?: never;
}
export interface OperationMfaStatusApiV1AuthMfaGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": MfaStatus;
      };
    };
  };
  requestBody?: never;
}
export interface OperationMfaDisableApiV1AuthMfaDisablePost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_MfaDisable;
    };
  };
}
export interface Input_MfaDisable {
  code: string;
  password: string;
}
export interface OperationMfaEnableApiV1AuthMfaEnablePost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": MfaEnrollment;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_MfaCode;
    };
  };
}
export interface Input_MfaCode {
  code: string;
}
export interface OperationMfaNewRecoveryCodesApiV1AuthMfaRecoveryCodesPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": MfaEnabled;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_MfaCode;
    };
  };
}
export interface OperationMfaSetupApiV1AuthMfaSetupPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": MfaSetup;
      };
    };
  };
  requestBody?: never;
}
export interface OperationGetPreferencesApiV1AuthPreferencesGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": NotificationPrefs;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdatePreferencesApiV1AuthPreferencesPatch {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": NotificationPrefs;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_NotificationPrefsUpdate;
    };
  };
}
export interface Input_NotificationPrefsUpdate {
  digest_frequency?: ("off" | "daily" | "weekly") | null;
  notify_on_assignment?: boolean | null;
}
export interface OperationRefreshApiV1AuthRefreshPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LoginResponse;
      };
    };
  };
  requestBody?: never;
}
export interface OperationResetPasswordApiV1AuthResetPasswordPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ResetPassword;
    };
  };
}
export interface Input_ResetPassword {
  new_password: string;
  token: string;
}
export interface OperationListComponentsApiV1ComponentsGet {
  parameters: {
    query?: {
      /**
       * Name or purl
       */
      q?: string | null;
      ecosystem?: string | null;
      license?: string | null;
      asset_id?: number | null;
      /**
       * Only components with no licence recorded
       */
      unlicensed?: boolean;
      /**
       * Filter by what the licence policy says
       */
      licence_rule?: string | null;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_ComponentUse_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationGetLicensePolicyApiV1ComponentsLicensePolicyGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LicensePolicyOut;
      };
    };
  };
  requestBody?: never;
}
export interface OperationPutLicensePolicyApiV1ComponentsLicensePolicyPut {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LicensePolicyOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_LicensePolicyUpdate;
    };
  };
}
export interface Input_LicensePolicyUpdate {
  /**
   * @maxItems 500
   */
  rules: Input_LicenceRule[];
}
export interface Input_LicenceRule {
  licence: string;
  note?: string | null;
  rule: "allowed" | "denied" | "review";
}
export interface OperationListLicensesApiV1ComponentsLicensesGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": LicenceCount[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationStatsApiV1ComponentsStatsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": InventoryStats;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListFindingsApiV1FindingsGet {
  parameters: {
    query?: {
      sort?: string;
      page?: number;
      page_size?: number;
      /**
       * Full-text search (title, CVE, package, path, rule)
       */
      q?: string | null;
      severity?: Severity[];
      status?: Status[];
      type?: string | null;
      asset_id?: number[];
      product_id?: number | null;
      environment?: string | null;
      tool?: string | null;
      cwe?: string | null;
      cve?: string | null;
      package?: string | null;
      assignee_id?: number | null;
      unassigned?: boolean;
      overdue?: boolean | null;
      first_seen_from?: string | null;
      first_seen_to?: string | null;
      /**
       * Repeatable; findings must carry every tag
       */
      tag?: string[];
      /**
       * In CISA's Known Exploited Vulnerabilities catalogue
       */
      kev?: boolean | null;
      /**
       * Minimum EPSS probability (0-1)
       */
      epss_min?: number | null;
      /**
       * Findings whose linked ticket the tracker now reports as finished
       */
      ticket_done?: boolean | null;
      /**
       * Only findings reported by this scan
       */
      scan_id?: number | null;
      /**
       * Only findings not reported by this scan (with scan_id: a scan diff)
       */
      not_in_scan_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_FindingOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationBulkUpdateApiV1FindingsBulkPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": BulkResult;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_BulkUpdate;
    };
  };
}
export interface Input_BulkUpdate {
  /**
   * @maxItems 20
   */
  add_tags?: string[];
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at?: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override?: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  /**
   * @minItems 1
   * @maxItems 1000
   */
  ids: number[];
  justification?: string | null;
  /**
   * @maxItems 20
   */
  remove_tags?: string[];
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Input_Severity | null;
  severity_reason?: string | null;
  status?: Input_Status | null;
  unassign?: boolean;
}
export interface OperationBulkUpdateMatchingApiV1FindingsBulkMatchingPost {
  parameters: {
    query?: {
      /**
       * Full-text search (title, CVE, package, path, rule)
       */
      q?: string | null;
      severity?: Severity[];
      status?: Status[];
      type?: string | null;
      asset_id?: number[];
      product_id?: number | null;
      environment?: string | null;
      tool?: string | null;
      cwe?: string | null;
      cve?: string | null;
      package?: string | null;
      assignee_id?: number | null;
      unassigned?: boolean;
      overdue?: boolean | null;
      first_seen_from?: string | null;
      first_seen_to?: string | null;
      /**
       * Repeatable; findings must carry every tag
       */
      tag?: string[];
      /**
       * In CISA's Known Exploited Vulnerabilities catalogue
       */
      kev?: boolean | null;
      /**
       * Minimum EPSS probability (0-1)
       */
      epss_min?: number | null;
      /**
       * Findings whose linked ticket the tracker now reports as finished
       */
      ticket_done?: boolean | null;
      /**
       * Only findings reported by this scan
       */
      scan_id?: number | null;
      /**
       * Only findings not reported by this scan (with scan_id: a scan diff)
       */
      not_in_scan_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": BulkResult;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_BulkChange;
    };
  };
}
/**
 * One change applied to many findings.
 */
export interface Input_BulkChange {
  /**
   * @maxItems 20
   */
  add_tags?: string[];
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at?: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override?: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  justification?: string | null;
  /**
   * @maxItems 20
   */
  remove_tags?: string[];
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Input_Severity | null;
  severity_reason?: string | null;
  status?: Input_Status | null;
  unassign?: boolean;
}
export interface OperationExportCsvApiV1FindingsExportCsvGet {
  parameters: {
    query?: {
      sort?: string;
      /**
       * Full-text search (title, CVE, package, path, rule)
       */
      q?: string | null;
      severity?: Severity[];
      status?: Status[];
      type?: string | null;
      asset_id?: number[];
      product_id?: number | null;
      environment?: string | null;
      tool?: string | null;
      cwe?: string | null;
      cve?: string | null;
      package?: string | null;
      assignee_id?: number | null;
      unassigned?: boolean;
      overdue?: boolean | null;
      first_seen_from?: string | null;
      first_seen_to?: string | null;
      /**
       * Repeatable; findings must carry every tag
       */
      tag?: string[];
      /**
       * In CISA's Known Exploited Vulnerabilities catalogue
       */
      kev?: boolean | null;
      /**
       * Minimum EPSS probability (0-1)
       */
      epss_min?: number | null;
      /**
       * Findings whose linked ticket the tracker now reports as finished
       */
      ticket_done?: boolean | null;
      /**
       * Only findings reported by this scan
       */
      scan_id?: number | null;
      /**
       * Only findings not reported by this scan (with scan_id: a scan diff)
       */
      not_in_scan_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationExportJsonApiV1FindingsExportJsonGet {
  parameters: {
    query?: {
      sort?: string;
      /**
       * Full-text search (title, CVE, package, path, rule)
       */
      q?: string | null;
      severity?: Severity[];
      status?: Status[];
      type?: string | null;
      asset_id?: number[];
      product_id?: number | null;
      environment?: string | null;
      tool?: string | null;
      cwe?: string | null;
      cve?: string | null;
      package?: string | null;
      assignee_id?: number | null;
      unassigned?: boolean;
      overdue?: boolean | null;
      first_seen_from?: string | null;
      first_seen_to?: string | null;
      /**
       * Repeatable; findings must carry every tag
       */
      tag?: string[];
      /**
       * In CISA's Known Exploited Vulnerabilities catalogue
       */
      kev?: boolean | null;
      /**
       * Minimum EPSS probability (0-1)
       */
      epss_min?: number | null;
      /**
       * Findings whose linked ticket the tracker now reports as finished
       */
      ticket_done?: boolean | null;
      /**
       * Only findings reported by this scan
       */
      scan_id?: number | null;
      /**
       * Only findings not reported by this scan (with scan_id: a scan diff)
       */
      not_in_scan_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationExportSarifApiV1FindingsExportSarifGet {
  parameters: {
    query?: {
      sort?: string;
      /**
       * Full-text search (title, CVE, package, path, rule)
       */
      q?: string | null;
      severity?: Severity[];
      status?: Status[];
      type?: string | null;
      asset_id?: number[];
      product_id?: number | null;
      environment?: string | null;
      tool?: string | null;
      cwe?: string | null;
      cve?: string | null;
      package?: string | null;
      assignee_id?: number | null;
      unassigned?: boolean;
      overdue?: boolean | null;
      first_seen_from?: string | null;
      first_seen_to?: string | null;
      /**
       * Repeatable; findings must carry every tag
       */
      tag?: string[];
      /**
       * In CISA's Known Exploited Vulnerabilities catalogue
       */
      kev?: boolean | null;
      /**
       * Minimum EPSS probability (0-1)
       */
      epss_min?: number | null;
      /**
       * Findings whose linked ticket the tracker now reports as finished
       */
      ticket_done?: boolean | null;
      /**
       * Only findings reported by this scan
       */
      scan_id?: number | null;
      /**
       * Only findings not reported by this scan (with scan_id: a scan diff)
       */
      not_in_scan_id?: number | null;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListTagsApiV1FindingsTagsGet {
  parameters: {
    query?: {
      q?: string | null;
      limit?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TagCount[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationGetFindingApiV1Findings_FindingId_Get {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": FindingDetail;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateFindingApiV1Findings_FindingId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": FindingDetail;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_FindingUpdate;
    };
  };
}
export interface Input_FindingUpdate {
  assignee_id?: number | null;
  /**
   * Remove the override and return to the SLA due date
   */
  clear_due_at?: boolean;
  /**
   * Return to the severity the scanners report
   */
  clear_severity_override?: boolean;
  /**
   * Override the SLA due date (manager or higher)
   */
  due_at?: string | null;
  due_reason?: string | null;
  justification?: string | null;
  risk_accepted_until?: string | null;
  /**
   * Override the severity (manager or higher)
   */
  severity?: Input_Severity | null;
  severity_reason?: string | null;
  status?: Input_Status | null;
  /**
   * Replaces the finding's tags
   */
  tags?: string[] | null;
  unassign?: boolean;
}
export interface OperationCreateRequestApiV1Findings_FindingId_AcceptanceRequestsPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": AcceptanceRequestOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_AcceptanceRequestCreate;
    };
  };
}
export interface Input_AcceptanceRequestCreate {
  justification: string;
  /**
   * When the acceptance should end; may be required by policy
   */
  until?: string | null;
}
export interface OperationAddCommentApiV1Findings_FindingId_CommentsPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": FindingEventOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_CommentCreate;
    };
  };
}
export interface Input_CommentCreate {
  text: string;
}
export interface OperationFindingEventsApiV1Findings_FindingId_EventsGet {
  parameters: {
    query?: {
      page?: number;
      page_size?: number;
    };
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_FindingEventOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateTicketApiV1Findings_FindingId_TicketPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": FindingLinkOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TicketCreate;
    };
  };
}
export interface Input_TicketCreate {
  /**
   * Defaults to the only tracker available
   */
  integration_id?: number | null;
}
export interface OperationUnlinkTicketApiV1Findings_FindingId_Ticket_LinkId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
      link_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListTrackersApiV1Findings_FindingId_TrackersGet {
  parameters: {
    query?: never;
    header?: never;
    path: {
      finding_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": IntegrationOut[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListPoliciesApiV1GatePoliciesGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": GatePolicyOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpsertPolicyApiV1GatePoliciesPut {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": GatePolicyOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_GatePolicyUpsert;
    };
  };
}
export interface Input_GatePolicyUpsert {
  /**
   * null is the global policy, used by assets without one
   */
  asset_id?: number | null;
  conditions?: Input_GateConditions;
  enabled?: boolean;
}
/**
 * All conditions are optional; a policy with none always passes.
 */
export interface Input_GateConditions {
  /**
   * Fail when the report lists a component whose licence the licence policy denies
   */
  fail_on_denied_license?: boolean;
  /**
   * Fail when the asset carries an open finding whose CVE is in CISA's Known Exploited Vulnerabilities catalogue
   */
  fail_on_kev?: boolean;
  /**
   * Fail when this scan introduces a hard-coded credential (CWE-798, CWE-259 or CWE-321, as Gitleaks and secret scanners report them)
   */
  fail_on_new_secrets?: boolean;
  /**
   * Fail when the asset has findings past their SLA
   */
  fail_on_overdue?: boolean;
  /**
   * Fail when the scan reopens a resolved finding
   */
  fail_on_reopened?: boolean;
  /**
   * Most new findings this scan may introduce, per severity
   */
  max_new?: {
    [k: string]: number;
  };
  /**
   * Fail when this scan introduces a finding with a CVSS score above this
   */
  max_new_cvss?: number | null;
  /**
   * Most active findings the asset may carry, per severity
   */
  max_open?: {
    [k: string]: number;
  };
  /**
   * Fail when the asset carries an open finding whose EPSS probability is above this (0-1). Scores arrive with the daily intel sync, so a CVE first seen today counts from tomorrow
   */
  max_open_epss?: number | null;
}
export interface OperationDeletePolicyApiV1GatePolicies_PolicyId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      policy_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListIntegrationsApiV1IntegrationsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": IntegrationOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateIntegrationApiV1IntegrationsPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": IntegrationOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_IntegrationCreate;
    };
  };
}
export interface Input_IntegrationCreate {
  /**
   * null offers this tracker for every asset
   */
  asset_id?: number | null;
  /**
   * Open a ticket for each new finding whose CVE is in CISA KEV
   */
  auto_ticket_kev?: boolean;
  /**
   * Open a ticket for each new finding at or above this severity
   */
  auto_ticket_min_severity?: Input_Severity | null;
  base_url: string;
  /**
   * Resolve a finding when polling finds its ticket closed (needs TRACKER_POLL_HOURS)
   */
  close_resolves_finding?: boolean;
  /**
   * Jira: transition that closes
   */
  done_transition?: string | null;
  enabled?: boolean;
  /**
   * Jira issue type, e.g. "Bug"
   */
  issue_type?: string | null;
  kind: "jira" | "github" | "gitlab";
  /**
   * @maxItems 20
   */
  labels?: string[];
  name: string;
  /**
   * Jira key, owner/repo, or GitLab path
   */
  project: string;
  /**
   * Jira: transition that reopens
   */
  reopen_transition?: string | null;
  /**
   * Report scan and gate results on commits and pull requests (GitHub/GitLab)
   */
  scm_feedback?: boolean;
  /**
   * API token; stored encrypted
   */
  token: string;
  /**
   * Jira account email; blank for a PAT
   */
  username?: string | null;
}
export interface OperationDeleteIntegrationApiV1Integrations_IntegrationId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      integration_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateIntegrationApiV1Integrations_IntegrationId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      integration_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": IntegrationOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_IntegrationUpdate;
    };
  };
}
export interface Input_IntegrationUpdate {
  asset_id?: number | null;
  auto_ticket_kev?: boolean | null;
  /**
   * null (when given) turns it off
   */
  auto_ticket_min_severity?: Input_Severity | null;
  base_url?: string | null;
  close_resolves_finding?: boolean | null;
  /**
   * "" removes it
   */
  done_transition?: string | null;
  enabled?: boolean | null;
  issue_type?: string | null;
  labels?: string[] | null;
  name?: string | null;
  project?: string | null;
  /**
   * "" removes it
   */
  reopen_transition?: string | null;
  scm_feedback?: boolean | null;
  /**
   * Replaces the stored token
   */
  token?: string | null;
  username?: string | null;
}
export interface OperationCheckIntegrationApiV1Integrations_IntegrationId_CheckPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      integration_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": IntegrationCheck;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationMetaApiV1MetaGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Meta;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListNotificationsApiV1NotificationsGet {
  parameters: {
    query?: {
      unread_only?: boolean;
      limit?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": NotificationList;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationMarkReadApiV1NotificationsReadPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": NotificationList;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_MarkRead;
    };
  };
}
export interface Input_MarkRead {
  /**
   * null marks every notification read
   */
  ids?: number[] | null;
}
export interface OperationListProductsApiV1ProductsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ProductOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateProductApiV1ProductsPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ProductOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ProductBody;
    };
  };
}
export interface Input_ProductBody {
  description?: string;
  name: string;
}
export interface OperationDeleteProductApiV1Products_ProductId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      product_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateProductApiV1Products_ProductId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      product_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ProductOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ProductUpdate;
    };
  };
}
export interface Input_ProductUpdate {
  description?: string | null;
  name?: string | null;
}
export interface OperationListSchedulesApiV1ReportSchedulesGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScheduleOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateScheduleApiV1ReportSchedulesPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScheduleOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ScheduleBody;
    };
  };
}
export interface Input_ScheduleBody {
  enabled?: boolean;
  frequency?: "weekly" | "monthly";
  name: string;
  /**
   * Only this product; null for everything the reader sees
   */
  product_id?: number | null;
  /**
   * Guardiano users
   *
   * @minItems 1
   * @maxItems 50
   */
  recipient_ids: number[];
}
export interface OperationReplaceScheduleApiV1ReportSchedules_ScheduleId_Put {
  parameters: {
    query?: never;
    header?: never;
    path: {
      schedule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScheduleOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_ScheduleBody;
    };
  };
}
export interface OperationDeleteScheduleApiV1ReportSchedules_ScheduleId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      schedule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationSendNowApiV1ReportSchedules_ScheduleId_SendPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      schedule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "202": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": {
          [k: string]: unknown;
        };
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListScansApiV1ScansGet {
  parameters: {
    query?: {
      asset_id?: number | null;
      scan_type?: string | null;
      source?: string | null;
      page?: number;
      page_size?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_ScanOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUploadScanApiV1ScansPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScanOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "multipart/form-data": Input_BodyUploadScanApiV1ScansPost;
    };
  };
}
export interface Input_BodyUploadScanApiV1ScansPost {
  /**
   * Let close_missing act on a report with no findings (skipped by default)
   */
  allow_empty?: boolean;
  asset_id?: number | null;
  /**
   * Created automatically if it does not exist
   */
  asset_name?: string | null;
  branch?: string | null;
  /**
   * Resolve active findings from this tool not present in the report
   */
  close_missing?: boolean;
  commit_sha?: string | null;
  /**
   * SARIF, CycloneDX JSON, Trivy JSON, Semgrep JSON or Guardiano JSON
   */
  file: Blob;
  /**
   * Override auto-detection: sarif, cyclonedx, trivy, semgrep, grype, osv, dependency-check, npm-audit, gitleaks, checkov, kics, zap, nuclei, guardiano
   */
  format?: string | null;
  /**
   * Evaluate the report (and its quality gate) without changing the inventory. Implied when the asset has a default_branch and 'branch' differs from it.
   */
  preview?: boolean;
  scan_type?: string | null;
}
export interface OperationGetScanApiV1Scans_ScanId_Get {
  parameters: {
    query?: never;
    header?: never;
    path: {
      scan_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScanOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationScanDiffApiV1Scans_ScanId_DiffGet {
  parameters: {
    query?: {
      /**
       * Scan to compare with; defaults to the previous scan
       */
      against?: number | null;
    };
    header?: never;
    path: {
      scan_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": ScanDiff;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationSearchApiV1SearchGet {
  parameters: {
    query: {
      q: string;
      limit?: number;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SearchResult;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationGetSlaApiV1SlaGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SlaMatrix;
      };
    };
  };
  requestBody?: never;
}
export interface OperationPutSlaApiV1SlaPut {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SlaMatrix;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_SlaUpdate;
    };
  };
}
/**
 * Replaces every policy. ``null`` (or omission) means inherit: "any" falls back to SLA_*_DAYS.
 */
export interface Input_SlaUpdate {
  days: {
    [k: string]: {
      [k: string]: number | null;
    };
  };
}
export interface OperationListTeamsApiV1TeamsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TeamOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateTeamApiV1TeamsPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TeamOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TeamCreate;
    };
  };
}
export interface Input_TeamCreate {
  description?: string;
  name: string;
}
export interface OperationDeleteTeamApiV1Teams_TeamId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      team_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateTeamApiV1Teams_TeamId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      team_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TeamOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TeamUpdate;
    };
  };
}
export interface Input_TeamUpdate {
  description?: string | null;
  name?: string | null;
}
export interface OperationSetMembersApiV1Teams_TeamId_MembersPut {
  parameters: {
    query?: never;
    header?: never;
    path: {
      team_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TeamOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TeamMembers;
    };
  };
}
export interface Input_TeamMembers {
  /**
   * @maxItems 500
   */
  user_ids?: number[];
}
export interface OperationListTokensApiV1TokensGet {
  parameters: {
    query?: {
      all?: boolean;
    };
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TokenOut[];
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateTokenApiV1TokensPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TokenCreated;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TokenCreate;
    };
  };
}
export interface Input_TokenCreate {
  expires_in_days?: number | null;
  name: string;
  scopes?: Input_TokenScope[];
}
export interface OperationRevokeTokenApiV1Tokens_TokenId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      token_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListRulesApiV1TriageRulesGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TriageRuleOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateRuleApiV1TriageRulesPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TriageRuleOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TriageRuleCreate;
    };
  };
}
export interface Input_TriageRuleCreate {
  action?: Input_RuleAction;
  /**
   * null applies the rule to every asset
   */
  asset_id?: number | null;
  enabled?: boolean;
  expires_at?: string | null;
  match?: Input_RuleMatch;
  name: string;
  /**
   * Lowest runs first
   */
  priority?: number;
}
/**
 * What to do with a matching finding. At least one effect must be given.
 */
export interface Input_RuleAction {
  assignee_id?: number | null;
  justification?: string | null;
  /**
   * Override the scanner's severity
   */
  severity?: Input_Severity | null;
  /**
   * Only false_positive: risk acceptance needs a person and an expiry date
   */
  status?: "false_positive" | null;
  /**
   * @maxItems 20
   */
  tags?: string[];
}
/**
 * Conditions a finding must all satisfy. At least one must be given.
 */
export interface Input_RuleMatch {
  asset_criticality?: Input_Criticality[];
  /**
   * The asset must carry every one of these tags
   *
   * @maxItems 20
   */
  asset_tags?: string[];
  /**
   * Exact CVE id, e.g. "CVE-2021-44228"
   */
  cve?: string | null;
  /**
   * "89" or "CWE-89"
   */
  cwe?: string | null;
  /**
   * e.g. "npm", "pypi", "maven"
   */
  ecosystem?: string | null;
  /**
   * Only CVEs with at least this EPSS
   */
  epss_min?: number | null;
  /**
   * true: only CVEs in CISA's KEV catalogue; false: only CVEs that are not
   */
  kev?: boolean | null;
  package?: string | null;
  /**
   * e.g. "tests/*" or "* /vendor/*"
   */
  path_glob?: string | null;
  rule_id?: string | null;
  severity?: Input_Severity[];
  title_contains?: string | null;
  tool?: string | null;
  type?: Input_ScanType | null;
}
export interface OperationPreviewApiV1TriageRulesPreviewPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TriagePreviewOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TriagePreviewRequest;
    };
  };
}
export interface Input_TriagePreviewRequest {
  asset_id?: number | null;
  /**
   * How many matching findings to return
   */
  limit?: number;
  match: Input_RuleMatch;
}
export interface OperationDeleteRuleApiV1TriageRules_RuleId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      rule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateRuleApiV1TriageRules_RuleId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      rule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TriageRuleOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_TriageRuleUpdate;
    };
  };
}
/**
 * Only the fields given are changed; match and action are replaced wholesale.
 */
export interface Input_TriageRuleUpdate {
  action?: Input_RuleAction | null;
  asset_id?: number | null;
  clear_expiry?: boolean;
  enabled?: boolean | null;
  expires_at?: string | null;
  match?: Input_RuleMatch | null;
  name?: string | null;
  priority?: number | null;
}
export interface OperationApplyToExistingApiV1TriageRules_RuleId_ApplyPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      rule_id: number;
    };
    cookie?: never;
  };
  responses: {
    "202": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": TriageApplyOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListUsersApiV1UsersGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": UserOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateUserApiV1UsersPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": UserOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_UserCreate;
    };
  };
}
export interface Input_UserCreate {
  email: string;
  full_name?: string;
  password: string;
  role?: "admin" | "manager" | "analyst" | "viewer";
}
export interface OperationDirectoryApiV1UsersDirectoryGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": UserBrief[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationDeleteUserApiV1Users_UserId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      user_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateUserApiV1Users_UserId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      user_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": UserOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_UserUpdate;
    };
  };
}
export interface Input_UserUpdate {
  full_name?: string | null;
  is_active?: boolean | null;
  password?: string | null;
  role?: Input_Role | null;
}
export interface OperationListViewsApiV1ViewsGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SavedViewOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateViewApiV1ViewsPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SavedViewOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_SavedViewCreate;
    };
  };
}
export interface Input_SavedViewCreate {
  name: string;
  /**
   * Findings page query string, e.g. severity=high&status=open
   */
  query?: string;
  shared?: boolean;
}
export interface OperationDeleteViewApiV1Views_ViewId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      view_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateViewApiV1Views_ViewId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      view_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": SavedViewOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_SavedViewUpdate;
    };
  };
}
export interface Input_SavedViewUpdate {
  name?: string | null;
  query?: string | null;
  shared?: boolean | null;
}
export interface OperationGetVulnerabilityApiV1Vulnerabilities_VulnId_Get {
  parameters: {
    query?: {
      page?: number;
      page_size?: number;
    };
    header?: never;
    path: {
      vuln_id: string;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Vulnerability;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationListWebhooksApiV1WebhooksGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": WebhookOut[];
      };
    };
  };
  requestBody?: never;
}
export interface OperationCreateWebhookApiV1WebhooksPost {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "201": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": WebhookCreated;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_WebhookCreate;
    };
  };
}
export interface Input_WebhookCreate {
  /**
   * null sends events for every asset
   */
  asset_id?: number | null;
  enabled?: boolean;
  /**
   * @minItems 1
   */
  events: (
    | "scan.completed"
    | "gate.failed"
    | "finding.reopened"
    | "finding.status_changed"
    | "finding.assigned"
    | "finding.risk_acceptance_expiring"
    | "finding.kev_added"
    | "sla.breached"
    | "test"
  )[];
  format?: "guardiano" | "slack" | "teams";
  /**
   * Ignored by scan.completed, gate.failed and test events
   */
  min_severity?: "critical" | "high" | "medium" | "low" | "info";
  name: string;
  url: string;
}
export interface OperationDeleteWebhookApiV1Webhooks_WebhookId_Delete {
  parameters: {
    query?: never;
    header?: never;
    path: {
      webhook_id: number;
    };
    cookie?: never;
  };
  responses: {
    "204": {
      headers: {
        [k: string]: unknown;
      };
      content?: never;
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationUpdateWebhookApiV1Webhooks_WebhookId_Patch {
  parameters: {
    query?: never;
    header?: never;
    path: {
      webhook_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": WebhookOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody: {
    content: {
      "application/json": Input_WebhookUpdate;
    };
  };
}
export interface Input_WebhookUpdate {
  asset_id?: number | null;
  enabled?: boolean | null;
  events?:
    | (
        | "scan.completed"
        | "gate.failed"
        | "finding.reopened"
        | "finding.status_changed"
        | "finding.assigned"
        | "finding.risk_acceptance_expiring"
        | "finding.kev_added"
        | "sla.breached"
        | "test"
      )[]
    | null;
  format?: ("guardiano" | "slack" | "teams") | null;
  min_severity?: Input_Severity | null;
  name?: string | null;
  rotate_secret?: boolean;
  url?: string | null;
}
export interface OperationListDeliveriesApiV1Webhooks_WebhookId_DeliveriesGet {
  parameters: {
    query?: {
      page?: number;
      page_size?: number;
    };
    header?: never;
    path: {
      webhook_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": Page_DeliveryOut_;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationRotateSecretApiV1Webhooks_WebhookId_RotateSecretPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      webhook_id: number;
    };
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": WebhookCreated;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationSendTestApiV1Webhooks_WebhookId_TestPost {
  parameters: {
    query?: never;
    header?: never;
    path: {
      webhook_id: number;
    };
    cookie?: never;
  };
  responses: {
    "202": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": DeliveryOut;
      };
    };
    "422": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": HTTPValidationError;
      };
    };
  };
  requestBody?: never;
}
export interface OperationHealthzHealthzGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": {
          [k: string]: string;
        };
      };
    };
  };
  requestBody?: never;
}
export interface OperationReadyzReadyzGet {
  parameters: {
    query?: never;
    header?: never;
    path?: never;
    cookie?: never;
  };
  responses: {
    "200": {
      headers: {
        [k: string]: unknown;
      };
      content: {
        "application/json": {
          [k: string]: string;
        };
      };
    };
  };
  requestBody?: never;
}

export type components = ApiContract["components"];
export type paths = ApiContract["paths"];
export type operations = ApiContract["operations"];
