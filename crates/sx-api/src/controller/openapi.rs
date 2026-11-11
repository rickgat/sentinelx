// LOW-009: the helpers in this module build JSON values they own and
// then index them via `Value`'s `IndexMut` (e.g. `op["parameters"] = …`).
// This is safe-by-construction — the keys come from the same builder
// that materialised the `Value`.
#![allow(clippy::indexing_slicing)]

//! OpenAPI 3.1 schema controller — `GET /openapi.json`.
//!
//! Hand-rolled JSON document (no `utoipa` macro dependency) so the
//! description is decoupled from individual handler signatures and
//! stays cheap to evolve. The schema covers **every** route registered
//! in [`crate::router`] across the eight operational modules
//! (Operations, Engagement, Discovery, Offensive, Detection, Identity,
//! Governance, Developer). Component schemas are referenced via `$ref`
//! and defined inline as JSON-Schema fragments.
//!
//! Exposed on the **public** subrouter so developer tooling (Swagger UI,
//! REST clients) can fetch the schema without first acquiring an access
//! token. The response itself contains no secrets — only public route
//! metadata — so this is safe.

use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Map, Value};

/// `GET /openapi.json` — return the OpenAPI 3.1 description as JSON.
///
/// The handler is allocation-light: it builds a fresh `serde_json::Value`
/// per call. Throughput is dominated by JSON serialisation, which is
/// fine for a doc endpoint hit infrequently by tooling.
pub async fn schema() -> impl IntoResponse {
    let document = build_document();
    // Explicit `application/json` content-type — Swagger UI is strict
    // about MIME sniffing and a plain `Json(..)` response already supplies
    // it, but we add an explicit header tuple to make the contract
    // self-documenting for ops dashboards.
    ([(header::CONTENT_TYPE, "application/json")], Json(document))
}

/// Build the full OpenAPI document.
fn build_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "SentinelX API",
            "version": "1.1.0",
            "description": "Autonomous Security Validation Platform — v1 HTTP API. \
                            Coverage spans all P0-P3 modules: Operations (SOC, safety, \
                            kill-switch, approvals), Engagement (engagements, findings, \
                            remediation, reports, copilot), Discovery (assets, scans, \
                            cloud inventory/drift, vulnerability & Prowler import, \
                            intel feeds, logs/OCSF), Offensive (BAS techniques & chains, \
                            red-team chain compose, graph attack-paths, blast-radius, \
                            DAST), Detection (UEBA, device-trust, runtime/falco, hunt, \
                            ML predict), Identity (auth/login, MFA, WebAuthn, SAML, SCIM, \
                            adaptive auth/RBA, IAM roles/users), Governance (compliance \
                            frameworks & evidence, audit search/replay/anchors, GRC push, \
                            IR playbooks, DLP), Developer (OpenAPI, plugins, chaos, risk \
                            tuning, mobile push, bug-bounty integrations). \
                            Served on `:8080` by `sx-monolith` (or `sx-api`).",
            "contact": {
                "name": "SentinelX Engineering",
                "url": "https://sentinelx.example.com"
            },
            "license": {
                "name": "PolyForm Noncommercial 1.0.0",
                "url": "https://polyformproject.org/licenses/noncommercial/1.0.0"
            }
        },
        "servers": [
            { "url": "/", "description": "Same-origin (proxy)" },
            { "url": "http://127.0.0.1:8080", "description": "Local sx-monolith (default port)" }
        ],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            },
            "schemas": build_schemas()
        },
        "security": [
            { "bearerAuth": [] }
        ],
        "tags": build_tags(),
        "paths": build_paths()
    })
}

/// Hand-rolled component schemas referenced by the path operations.
///
/// Split across helper functions to keep each `json!{..}` expansion
/// well within the proc-macro recursion budget.
fn build_schemas() -> Value {
    let mut merged = Map::new();
    for chunk in [
        schemas_chunk_a(),
        schemas_chunk_b(),
        schemas_chunk_c(),
        schemas_chunk_d(),
        schemas_chunk_e(),
        schemas_chunk_f(),
        schemas_chunk_g(),
        schemas_chunk_h(),
        schemas_chunk_i(),
        schemas_chunk_j(),
        schemas_chunk_pentest(),
    ] {
        if let Value::Object(obj) = chunk {
            for (k, v) in obj {
                merged.insert(k, v);
            }
        }
    }
    Value::Object(merged)
}

fn schemas_chunk_a() -> Value {
    json!({
        "ApiError": {
            "type": "object",
            "required": ["error"],
            "properties": {
                "error": {
                    "type": "object",
                    "required": ["code", "message", "request_id"],
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" },
                        "request_id": { "type": "string" },
                        "details": {}
                    }
                }
            }
        },
        "EnvelopeMeta": {
            "type": "object",
            "required": ["request_id", "ts"],
            "properties": {
                "request_id": { "type": "string" },
                "ts": { "type": "string", "format": "date-time" }
            }
        },
        "GenericData": {
            "type": "object",
            "description": "Module-specific response payload — see crate-level view types.",
            "additionalProperties": true
        },
        "GenericRequest": {
            "type": "object",
            "description": "Module-specific request body — see crate-level command/DTO types.",
            "additionalProperties": true
        }
    })
}

fn schemas_chunk_b() -> Value {
    json!({
        "LoginRequest": {
            "type": "object",
            "required": ["email", "password"],
            "properties": {
                "email": { "type": "string", "format": "email" },
                "password": { "type": "string", "format": "password" }
            }
        },
        "TokenView": {
            "type": "object",
            "required": ["access_token", "refresh_token", "token_type", "expires_in"],
            "properties": {
                "access_token": { "type": "string" },
                "refresh_token": { "type": "string" },
                "token_type": { "type": "string", "enum": ["Bearer"] },
                "expires_in": { "type": "integer", "format": "int64" }
            }
        },
        "RefreshRequest": {
            "type": "object",
            "required": ["refresh_token"],
            "properties": {
                "refresh_token": { "type": "string" }
            }
        },
        "OidcExchangeRequest": {
            "type": "object",
            "required": ["code", "redirect_uri"],
            "properties": {
                "code": { "type": "string" },
                "redirect_uri": { "type": "string", "format": "uri" }
            }
        },
        "SignupRequest": {
            "type": "object",
            "required": ["email", "password"],
            "properties": {
                "email": { "type": "string", "format": "email" },
                "password": { "type": "string", "format": "password" },
                "company": { "type": "string" }
            }
        },
        "ForgotPasswordRequest": {
            "type": "object",
            "required": ["email"],
            "properties": {
                "email": { "type": "string", "format": "email" }
            }
        },
        "ResetPasswordRequest": {
            "type": "object",
            "required": ["token", "new_password"],
            "properties": {
                "token": { "type": "string" },
                "new_password": { "type": "string", "format": "password" }
            }
        },
        "VerifyEmailRequest": {
            "type": "object",
            "required": ["token"],
            "properties": {
                "token": { "type": "string" }
            }
        }
    })
}

fn schemas_chunk_c() -> Value {
    json!({
        "Engagement": {
            "type": "object",
            "required": ["id", "tenant_id", "name", "status"],
            "properties": {
                "id": { "type": "string" },
                "tenant_id": { "type": "string" },
                "name": { "type": "string" },
                "status": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "CreateEngagement": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "description": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } }
            }
        },
        "UpdateEngagement": {
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "description": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } }
            }
        },
        "Finding": {
            "type": "object",
            "required": ["id", "severity", "title", "status"],
            "properties": {
                "id": { "type": "string" },
                "severity": { "type": "string" },
                "title": { "type": "string" },
                "status": { "type": "string" },
                "engagement_id": { "type": "string" }
            }
        },
        "FindingBulkUpdate": {
            "type": "object",
            "required": ["ids", "status"],
            "properties": {
                "ids": { "type": "array", "items": { "type": "string" } },
                "status": { "type": "string" }
            }
        },
        "FindingStatusUpdate": {
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": { "type": "string" },
                "comment": { "type": "string" }
            }
        },
        "FindingRemediationLink": {
            "type": "object",
            "required": ["advisory_id"],
            "properties": {
                "advisory_id": { "type": "string" },
                "notes": { "type": "string" }
            }
        }
    })
}

fn schemas_chunk_d() -> Value {
    json!({
        "Asset": {
            "type": "object",
            "required": ["id", "name", "kind"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "kind": { "type": "string" },
                "tags": { "type": "array", "items": { "type": "string" } }
            }
        },
        "CreateAsset": {
            "type": "object",
            "required": ["name", "kind"],
            "properties": {
                "name": { "type": "string" },
                "kind": { "type": "string" },
                "tags": { "type": "array", "items": { "type": "string" } }
            }
        },
        "BulkAssetImport": {
            "type": "object",
            "required": ["assets"],
            "properties": {
                "assets": { "type": "array", "items": { "$ref": "#/components/schemas/CreateAsset" } }
            }
        },
        "RiskCalculateRequest": {
            "type": "object",
            "required": ["engagement_id"],
            "properties": {
                "engagement_id": { "type": "string" },
                "cvss": { "type": "number" },
                "epss": { "type": "number" },
                "exposure": { "type": "number" },
                "criticality": { "type": "number" }
            }
        },
        "RiskCalculateResponse": {
            "type": "object",
            "required": ["engagement_id", "composite_score", "components"],
            "properties": {
                "engagement_id": { "type": "string" },
                "composite_score": { "type": "number" },
                "components": {
                    "type": "object",
                    "properties": {
                        "cvss": { "type": "number" },
                        "epss": { "type": "number" },
                        "exposure": { "type": "number" },
                        "criticality": { "type": "number" }
                    }
                }
            }
        }
    })
}

fn schemas_chunk_e() -> Value {
    json!({
        "BasRunRequest": {
            "type": "object",
            "required": ["technique_id"],
            "properties": {
                "technique_id": { "type": "string" },
                "engagement_id": { "type": "string" },
                "approval_token": { "type": "string" }
            }
        },
        "BasRunResponse": {
            "type": "object",
            "required": ["simulation_id", "outcome", "evidence_count"],
            "properties": {
                "simulation_id": { "type": "string" },
                "outcome": { "type": "string" },
                "evidence_count": { "type": "integer", "format": "int32" }
            }
        },
        "BasApprovalRecord": {
            "type": "object",
            "required": ["token", "decision"],
            "properties": {
                "token": { "type": "string" },
                "decision": { "type": "string", "enum": ["approve", "deny"] },
                "reason": { "type": "string" }
            }
        },
        "BasChainView": {
            "type": "object",
            "required": ["id", "name", "techniques"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "techniques": { "type": "array", "items": { "type": "string" } }
            }
        },
        "BasChainRunRequest": {
            "type": "object",
            "properties": {
                "engagement_id": { "type": "string" },
                "approval_token": { "type": "string" }
            }
        },
        "SocAlert": {
            "type": "object",
            "required": ["id", "severity", "title"],
            "properties": {
                "id": { "type": "string" },
                "severity": { "type": "string" },
                "title": { "type": "string" },
                "tenant_id": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "SocEvent": {
            "type": "object",
            "required": ["source", "payload"],
            "properties": {
                "source": { "type": "string" },
                "payload": { "type": "object", "additionalProperties": true }
            }
        },
        "CopilotChatRequest": {
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": { "type": "string", "minLength": 1 }
            }
        },
        "CopilotChatResponse": {
            "type": "object",
            "required": ["reply", "model"],
            "properties": {
                "reply": { "type": "string" },
                "model": { "type": "string" }
            }
        },
        "CopilotApprovalDecide": {
            "type": "object",
            "required": ["decision"],
            "properties": {
                "decision": { "type": "string", "enum": ["approve", "deny"] },
                "reason": { "type": "string" }
            }
        }
    })
}

fn schemas_chunk_f() -> Value {
    json!({
        "CreateUserRequest": {
            "type": "object",
            "required": ["tenant_id", "email", "roles"],
            "properties": {
                "tenant_id": { "type": "string" },
                "email": { "type": "string", "format": "email" },
                "roles": { "type": "array", "items": { "type": "string" } }
            }
        },
        "CreateUserResponse": {
            "type": "object",
            "required": ["id", "tenant_id", "email", "roles", "created_at"],
            "properties": {
                "id": { "type": "string" },
                "tenant_id": { "type": "string" },
                "email": { "type": "string", "format": "email" },
                "roles": { "type": "array", "items": { "type": "string" } },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "Role": {
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "description": { "type": "string" },
                "permissions": { "type": "array", "items": { "type": "string" } }
            }
        },
        "CreateRoleRequest": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "description": { "type": "string" },
                "permissions": { "type": "array", "items": { "type": "string" } }
            }
        },
        "RoleAssignRequest": {
            "type": "object",
            "required": ["role_id"],
            "properties": {
                "role_id": { "type": "string" }
            }
        },
        "TenantView": {
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "CreateTenantRequest": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string" }
            }
        },
        "UpdateTenantRequest": {
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        },
        "ScimUser": {
            "type": "object",
            "required": ["id", "userName"],
            "properties": {
                "id": { "type": "string" },
                "userName": { "type": "string" },
                "active": { "type": "boolean" },
                "emails": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "ScimGroup": {
            "type": "object",
            "required": ["id", "displayName"],
            "properties": {
                "id": { "type": "string" },
                "displayName": { "type": "string" },
                "members": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "ScimToken": {
            "type": "object",
            "required": ["id", "label"],
            "properties": {
                "id": { "type": "string" },
                "label": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "WebAuthnRegisterStartRequest": {
            "type": "object",
            "properties": {
                "display_name": { "type": "string" }
            }
        },
        "WebAuthnFinishRequest": {
            "type": "object",
            "description": "Output of `navigator.credentials.create/get` (CredentialResponse).",
            "additionalProperties": true
        },
        "MfaEnrollRequest": {
            "type": "object",
            "properties": {
                "method": { "type": "string", "enum": ["totp", "webauthn"] }
            }
        },
        "MfaVerifyRequest": {
            "type": "object",
            "required": ["code"],
            "properties": {
                "code": { "type": "string" }
            }
        },
        "MfaStatusView": {
            "type": "object",
            "required": ["enabled"],
            "properties": {
                "enabled": { "type": "boolean" },
                "methods": { "type": "array", "items": { "type": "string" } }
            }
        }
    })
}

fn schemas_chunk_g() -> Value {
    json!({
        "FeedStatusView": {
            "type": "object",
            "required": ["id", "name", "kind", "last_run"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "kind": { "type": "string" },
                "last_run": { "type": "string", "format": "date-time" },
                "indicator_count": { "type": "integer", "format": "int64" }
            }
        },
        "IntelCheckRequest": {
            "type": "object",
            "required": ["indicator"],
            "properties": {
                "indicator": { "type": "string" },
                "kind": { "type": "string", "enum": ["ip", "domain", "url", "hash"] }
            }
        },
        "ReportSummaryView": {
            "type": "object",
            "required": ["id", "kind", "engagement_id"],
            "properties": {
                "id": { "type": "string" },
                "kind": { "type": "string" },
                "engagement_id": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" }
            }
        },
        "ReportRenderRequest": {
            "type": "object",
            "required": ["engagement_id", "format"],
            "properties": {
                "engagement_id": { "type": "string" },
                "format": { "type": "string", "enum": ["pdf", "html", "json", "markdown"] }
            }
        },
        "ReportDiffRequest": {
            "type": "object",
            "required": ["from_report_id", "to_report_id"],
            "properties": {
                "from_report_id": { "type": "string" },
                "to_report_id": { "type": "string" }
            }
        },
        "BrandingView": {
            "type": "object",
            "required": ["primary_color_hex"],
            "properties": {
                "logo_png_base64": { "type": "string", "nullable": true },
                "primary_color_hex": { "type": "string", "example": "#C71920" },
                "cover_md": { "type": "string", "nullable": true },
                "footer_md": { "type": "string", "nullable": true }
            }
        },
        "SetBrandingRequest": {
            "type": "object",
            "required": ["primary_color_hex"],
            "properties": {
                "logo_png_base64": { "type": "string", "nullable": true, "description": "Base64-encoded PNG, <= 200 KiB decoded" },
                "primary_color_hex": { "type": "string", "pattern": "^#[0-9a-fA-F]{6}$" },
                "cover_md": { "type": "string", "nullable": true },
                "footer_md": { "type": "string", "nullable": true }
            }
        },
        "ComprehensiveReportView": {
            "type": "object",
            "required": ["generated_at", "tenant_id", "total_findings", "posture_score", "markdown"],
            "properties": {
                "generated_at": { "type": "string", "format": "date-time" },
                "tenant_id": { "type": "string" },
                "total_findings": { "type": "integer", "format": "int64" },
                "posture_score": { "type": "integer", "format": "int64" },
                "by_severity": { "type": "array", "items": { "type": "object" } },
                "compliance": { "type": "array", "items": { "type": "object" } },
                "markdown": { "type": "string" }
            }
        },
        "ReportScheduleView": {
            "type": "object",
            "required": ["id", "format", "cron_expr", "recipients", "enabled", "next_run_at"],
            "properties": {
                "id": { "type": "string" },
                "engagement_id": { "type": "string", "nullable": true },
                "format": { "type": "string" },
                "cron_expr": { "type": "string" },
                "recipients": { "type": "array", "items": { "type": "string" } },
                "enabled": { "type": "boolean" },
                "next_run_at": { "type": "string" }
            }
        },
        "CreateReportScheduleRequest": {
            "type": "object",
            "required": ["engagement_id", "format", "cron_expr", "recipients"],
            "properties": {
                "engagement_id": { "type": "string" },
                "format": { "type": "string", "example": "executive_pdf" },
                "cron_expr": { "type": "string", "example": "0 0 8 * * 1" },
                "recipients": { "type": "array", "items": { "type": "string" } }
            }
        },
        "WorkflowSummaryView": {
            "type": "object",
            "required": ["id", "name", "version"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "version": { "type": "integer", "format": "int32" }
            }
        },
        "SoarWorkflowCreate": {
            "type": "object",
            "required": ["name", "definition"],
            "properties": {
                "name": { "type": "string" },
                "definition": { "type": "object", "additionalProperties": true }
            }
        },
        "SoarRunRequest": {
            "type": "object",
            "properties": {
                "context": { "type": "object", "additionalProperties": true }
            }
        },
        "DiscoveryRunRequest": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string" },
                "kind": { "type": "string" }
            }
        },
        "ScanHttpHeadersRequest": {
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": { "type": "string", "format": "uri" }
            }
        },
        "ApiDastScanRequest": {
            "type": "object",
            "required": ["base_url"],
            "properties": {
                "base_url": { "type": "string", "format": "uri" },
                "openapi_spec_url": { "type": "string", "format": "uri" }
            }
        },
        "ApiDastScanResultView": {
            "type": "object",
            "required": ["id", "status"],
            "properties": {
                "id": { "type": "string" },
                "status": { "type": "string" },
                "issue_count": { "type": "integer", "format": "int32" }
            }
        },
        "ProwlerImportRequest": {
            "type": "object",
            "required": ["findings"],
            "properties": {
                "provider": { "type": "string", "enum": ["aws", "gcp", "azure"] },
                "findings": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "VulnImportRequest": {
            "type": "object",
            "required": ["source", "items"],
            "properties": {
                "source": { "type": "string" },
                "items": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "CloudInventoryRequest": {
            "type": "object",
            "properties": {
                "provider": { "type": "string" },
                "regions": { "type": "array", "items": { "type": "string" } }
            }
        },
        "CloudDriftScanRequest": {
            "type": "object",
            "properties": {
                "baseline_id": { "type": "string" }
            }
        },
        "BaselineUpload": {
            "type": "object",
            "required": ["snapshot"],
            "properties": {
                "snapshot": { "type": "object", "additionalProperties": true }
            }
        },
        "BlastRadiusRequest": {
            "type": "object",
            "required": ["asset_id"],
            "properties": {
                "asset_id": { "type": "string" },
                "max_depth": { "type": "integer", "format": "int32" }
            }
        },
        "AttackPathRequest": {
            "type": "object",
            "required": ["source", "target"],
            "properties": {
                "source": { "type": "string" },
                "target": { "type": "string" }
            }
        },
        "RedTeamChainRequest": {
            "type": "object",
            "required": ["objectives"],
            "properties": {
                "objectives": { "type": "array", "items": { "type": "string" } },
                "engagement_id": { "type": "string" }
            }
        },
        "RemediationAdvisoryRequest": {
            "type": "object",
            "required": ["finding_id"],
            "properties": {
                "finding_id": { "type": "string" }
            }
        }
    })
}

fn schemas_chunk_h() -> Value {
    json!({
        "UebaAnomalyView": {
            "type": "object",
            "required": ["id", "user_id", "score"],
            "properties": {
                "id": { "type": "string" },
                "user_id": { "type": "string" },
                "score": { "type": "number" },
                "kind": { "type": "string" }
            }
        },
        "DeviceTrustPolicy": {
            "type": "object",
            "required": ["require_managed", "require_disk_encryption"],
            "properties": {
                "require_managed": { "type": "boolean" },
                "require_disk_encryption": { "type": "boolean" },
                "min_os_version": { "type": "string" }
            }
        },
        "RuntimeFalcoAlert": {
            "type": "object",
            "required": ["rule", "priority"],
            "properties": {
                "rule": { "type": "string" },
                "priority": { "type": "string" },
                "output": { "type": "string" },
                "time": { "type": "string", "format": "date-time" }
            }
        },
        "FalcoOverrideView": {
            "type": "object",
            "required": ["rule_name", "subkey", "action", "reason", "set_by", "set_at"],
            "properties": {
                "rule_name": { "type": "string" },
                "subkey": { "type": "string" },
                "action": { "type": "string", "enum": ["allow", "deny", "escalate", "downgrade"] },
                "reason": { "type": "string" },
                "set_by": { "type": "string", "format": "uuid" },
                "set_at": { "type": "string", "format": "date-time" }
            }
        },
        "PutFalcoOverrideRequest": {
            "type": "object",
            "required": ["rule_name", "subkey", "action", "reason"],
            "properties": {
                "rule_name": { "type": "string", "minLength": 1, "maxLength": 256 },
                "subkey": { "type": "string", "minLength": 1, "maxLength": 128 },
                "action": { "type": "string", "enum": ["allow", "deny", "escalate", "downgrade"] },
                "reason": { "type": "string", "minLength": 1, "maxLength": 1024 }
            }
        },
        "DeleteFalcoOverrideRequest": {
            "type": "object",
            "required": ["rule_name", "subkey"],
            "properties": {
                "rule_name": { "type": "string", "minLength": 1, "maxLength": 256 },
                "subkey": { "type": "string", "minLength": 1, "maxLength": 128 }
            }
        },
        "DeleteFalcoOverrideResponse": {
            "type": "object",
            "required": ["removed"],
            "properties": {
                "removed": { "type": "boolean" }
            }
        },
        "HuntQueryRequest": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": { "type": "string" },
                "limit": { "type": "integer", "format": "int32" }
            }
        },
        "DlpScanRequest": {
            "type": "object",
            "required": ["content"],
            "properties": {
                "content": { "type": "string" },
                "context": { "type": "string" }
            }
        },
        "DlpConfig": {
            "type": "object",
            "properties": {
                "enabled": { "type": "boolean" },
                "rules": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "RbaConfig": {
            "type": "object",
            "properties": {
                "block_threshold": { "type": "number" },
                "step_up_threshold": { "type": "number" }
            }
        },
        "ChaosConfig": {
            "type": "object",
            "properties": {
                "enabled": { "type": "boolean" },
                "failure_rate": { "type": "number" }
            }
        },
        "RiskTuningConfig": {
            "type": "object",
            "properties": {
                "weights": { "type": "object", "additionalProperties": { "type": "number" } }
            }
        }
    })
}

fn schemas_chunk_i() -> Value {
    json!({
        "GrcConfig": {
            "type": "object",
            "required": ["kind"],
            "properties": {
                "kind": { "type": "string" },
                "endpoint": { "type": "string", "format": "uri" },
                "credentials_ref": { "type": "string" }
            }
        },
        "GrcPushRequest": {
            "type": "object",
            "required": ["kind", "payload"],
            "properties": {
                "kind": { "type": "string" },
                "payload": { "type": "object", "additionalProperties": true }
            }
        },
        "GrcConfigTestRequest": {
            "type": "object",
            "additionalProperties": true
        },
        "BugBountyConfig": {
            "type": "object",
            "required": ["platform"],
            "properties": {
                "platform": { "type": "string", "enum": ["hackerone", "bugcrowd", "intigriti"] },
                "handle": { "type": "string" },
                "api_token_ref": { "type": "string" }
            }
        },
        "BugBountyPushRequest": {
            "type": "object",
            "required": ["platform", "report"],
            "properties": {
                "platform": { "type": "string" },
                "report": { "type": "object", "additionalProperties": true }
            }
        },
        "ComplianceEvidenceBundleView": {
            "type": "object",
            "required": ["id", "framework", "created_at"],
            "properties": {
                "id": { "type": "string" },
                "framework": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" },
                "size_bytes": { "type": "integer", "format": "int64" }
            }
        },
        "ComplianceEvidenceCollectRequest": {
            "type": "object",
            "required": ["framework"],
            "properties": {
                "framework": { "type": "string" },
                "control_ids": { "type": "array", "items": { "type": "string" } }
            }
        },
        "ComplianceMapRequest": {
            "type": "object",
            "required": ["finding_id", "framework"],
            "properties": {
                "finding_id": { "type": "string" },
                "framework": { "type": "string" },
                "control_ids": { "type": "array", "items": { "type": "string" } }
            }
        },
        "AuditEvent": {
            "type": "object",
            "required": ["id", "actor", "action", "ts"],
            "properties": {
                "id": { "type": "string" },
                "actor": { "type": "string" },
                "action": { "type": "string" },
                "subject": { "type": "string" },
                "ts": { "type": "string", "format": "date-time" }
            }
        },
        "AuditAnchorView": {
            "type": "object",
            "required": ["run_id", "merkle_root", "ts"],
            "properties": {
                "run_id": { "type": "string" },
                "merkle_root": { "type": "string" },
                "ts": { "type": "string", "format": "date-time" }
            }
        },
        "IrPlaybookView": {
            "type": "object",
            "required": ["id", "name"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "steps": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "IrIncidentOpen": {
            "type": "object",
            "required": ["playbook_id", "title"],
            "properties": {
                "playbook_id": { "type": "string" },
                "title": { "type": "string" },
                "severity": { "type": "string" }
            }
        },
        "IrIncidentStepUpdate": {
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": { "type": "string" },
                "notes": { "type": "string" }
            }
        },
        "LogIngestRequest": {
            "type": "object",
            "required": ["source", "events"],
            "properties": {
                "source": { "type": "string" },
                "events": { "type": "array", "items": { "type": "object", "additionalProperties": true } }
            }
        },
        "PluginInstallRequest": {
            "type": "object",
            "required": ["manifest_url"],
            "properties": {
                "manifest_url": { "type": "string", "format": "uri" },
                "checksum_sha256": { "type": "string" }
            }
        },
        "PluginView": {
            "type": "object",
            "required": ["id", "name", "version"],
            "properties": {
                "id": { "type": "string" },
                "name": { "type": "string" },
                "version": { "type": "string" },
                "enabled": { "type": "boolean" }
            }
        },
        "PredictiveRequest": {
            "type": "object",
            "required": ["finding_id"],
            "properties": {
                "finding_id": { "type": "string" }
            }
        },
        "MlTriageRequest": {
            "type": "object",
            "required": ["finding_id"],
            "properties": {
                "finding_id": { "type": "string" }
            }
        },
        "AutonomyPrRequest": {
            "type": "object",
            "required": ["finding_id"],
            "properties": {
                "finding_id": { "type": "string" },
                "title": { "type": "string" }
            }
        },
        "ThreatNetworkSubmission": {
            "type": "object",
            "required": ["payload"],
            "properties": {
                "payload": { "type": "object", "additionalProperties": true }
            }
        },
        "ValidationSchedule": {
            "type": "object",
            "required": ["engine_id", "cron"],
            "properties": {
                "engine_id": { "type": "string" },
                "cron": { "type": "string" }
            }
        },
        "CollabTokenRequest": {
            "type": "object",
            "properties": {
                "ttl_seconds": { "type": "integer", "format": "int64" }
            }
        },
        "KillSwitchRequest": {
            "type": "object",
            "required": ["reason"],
            "properties": {
                "reason": { "type": "string" }
            }
        },
        "RemediationOutcomeMetrics": {
            "type": "object",
            "properties": {
                "total": { "type": "integer", "format": "int64" },
                "resolved": { "type": "integer", "format": "int64" },
                "regressed": { "type": "integer", "format": "int64" }
            }
        },
        "BugBountyInboundPayload": {
            "type": "object",
            "description": "Vendor-specific webhook payload (HackerOne, Bugcrowd, Intigriti).",
            "additionalProperties": true
        }
    })
}

/// AI-SEC-001 — AI security audit schemas.
fn schemas_chunk_j() -> Value {
    json!({
        "AiAssetView": {
            "type": "object",
            "required": ["id", "kind", "name", "provider", "discovered_at", "metadata"],
            "properties": {
                "id": { "type": "string" },
                "tenant_id": { "type": "string" },
                "kind": {
                    "type": "string",
                    "enum": [
                        "llm_api_endpoint", "model_registry", "vector_store",
                        "model_file", "agent_framework", "mcp_server"
                    ]
                },
                "name": { "type": "string" },
                "provider": { "type": "string" },
                "endpoint": { "type": "string" },
                "discovered_at": { "type": "string", "format": "date-time" },
                "metadata": { "type": "object", "additionalProperties": { "type": "string" } }
            }
        },
        "AiAssetListResponse": {
            "type": "object",
            "required": ["assets"],
            "properties": {
                "assets": { "type": "array", "items": { "$ref": "#/components/schemas/AiAssetView" } }
            }
        },
        "AiBomView": {
            "type": "object",
            "description": "CycloneDX-ML-style AI Bill of Materials.",
            "required": ["bomFormat", "specVersion", "version", "components"],
            "properties": {
                "bomFormat": { "type": "string", "enum": ["CycloneDX"] },
                "specVersion": { "type": "string" },
                "version": { "type": "integer", "format": "int64" },
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["bom-ref", "type", "name", "publisher", "properties"],
                        "properties": {
                            "bom-ref": { "type": "string" },
                            "type": { "type": "string" },
                            "name": { "type": "string" },
                            "publisher": { "type": "string" },
                            "properties": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" },
                                        "value": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "AiControlView": {
            "type": "object",
            "required": ["id", "title", "framework", "description"],
            "properties": {
                "id": { "type": "string" },
                "title": { "type": "string" },
                "framework": {
                    "type": "string",
                    "enum": ["nist_ai_rmf", "iso_42001", "eu_ai_act"]
                },
                "description": { "type": "string" }
            }
        },
        "AiControlListResponse": {
            "type": "object",
            "required": ["controls"],
            "properties": {
                "controls": { "type": "array", "items": { "$ref": "#/components/schemas/AiControlView" } }
            }
        },
        "ProbeOutcomeView": {
            "type": "object",
            "required": ["probe_id", "category", "success", "confidence", "refused", "signals", "owasp_id", "owasp_title", "atlas_id", "atlas_title"],
            "properties": {
                "probe_id": { "type": "string" },
                "category": { "type": "string" },
                "success": { "type": "boolean" },
                "confidence": { "type": "number", "format": "double" },
                "refused": { "type": "boolean" },
                "signals": { "type": "array", "items": { "type": "string" } },
                "owasp_id": { "type": "string" },
                "owasp_title": { "type": "string" },
                "atlas_id": { "type": "string" },
                "atlas_title": { "type": "string" }
            }
        },
        "ModelFileFindingView": {
            "type": "object",
            "required": ["kind", "severity", "detail", "owasp_id", "atlas_id"],
            "properties": {
                "kind": { "type": "string" },
                "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                "detail": { "type": "string" },
                "offset": { "type": "integer", "format": "int64" },
                "owasp_id": { "type": "string" },
                "atlas_id": { "type": "string" }
            }
        },
        "AiControlEvidenceView": {
            "type": "object",
            "required": ["control_id", "status", "detail", "collected_at"],
            "properties": {
                "control_id": { "type": "string" },
                "status": { "type": "string", "enum": ["pass", "fail", "not_applicable", "manual"] },
                "detail": { "type": "string" },
                "collected_at": { "type": "string", "format": "date-time" }
            }
        },
        "AiAuditReportView": {
            "type": "object",
            "required": ["assets", "aibom", "probe_results", "modelfile_findings", "control_evidence"],
            "properties": {
                "assets": { "type": "array", "items": { "$ref": "#/components/schemas/AiAssetView" } },
                "aibom": { "$ref": "#/components/schemas/AiBomView" },
                "probe_results": { "type": "array", "items": { "$ref": "#/components/schemas/ProbeOutcomeView" } },
                "modelfile_findings": { "type": "array", "items": { "$ref": "#/components/schemas/ModelFileFindingView" } },
                "control_evidence": { "type": "array", "items": { "$ref": "#/components/schemas/AiControlEvidenceView" } }
            }
        }
    })
}

/// Tag groupings displayed in Swagger UI.
/// Schemas for the combined pentest surface (PENTEST-001).
fn schemas_chunk_pentest() -> Value {
    json!({
        "PentestRunRequest": {
            "type": "object",
            "required": ["engagement_id", "name", "targets"],
            "properties": {
                "engagement_id": { "type": "string" },
                "name": { "type": "string" },
                "targets": { "type": "array", "items": { "type": "string" } },
                "phases": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional snake_case phase subset; empty runs the full plan."
                }
            }
        },
        "PentestFindingView": {
            "type": "object",
            "required": ["fingerprint", "asset", "check_id", "title", "severity", "sources", "evidence", "mitre", "validated"],
            "properties": {
                "fingerprint": { "type": "string" },
                "asset": { "type": "string" },
                "check_id": { "type": "string" },
                "title": { "type": "string" },
                "severity": { "type": "string" },
                "port": { "type": "integer", "nullable": true },
                "path": { "type": "string", "nullable": true },
                "sources": { "type": "array", "items": { "type": "string" } },
                "evidence": { "type": "array", "items": { "type": "string" } },
                "cve": { "type": "string", "nullable": true },
                "mitre": { "type": "array", "items": { "type": "string" } },
                "validated": { "type": "boolean" }
            }
        },
        "PentestRunView": {
            "type": "object",
            "required": ["id", "tenant_id", "engagement_id", "name", "actor", "status", "started_at", "phases", "findings", "narratives", "finding_count", "validated_count"],
            "properties": {
                "id": { "type": "string" },
                "tenant_id": { "type": "string" },
                "engagement_id": { "type": "string" },
                "name": { "type": "string" },
                "actor": { "type": "string" },
                "status": { "type": "string", "enum": ["running", "completed", "aborted"] },
                "started_at": { "type": "string", "format": "date-time" },
                "finished_at": { "type": "string", "format": "date-time", "nullable": true },
                "phases": { "type": "array", "items": { "type": "object" } },
                "findings": { "type": "array", "items": { "$ref": "#/components/schemas/PentestFindingView" } },
                "narratives": { "type": "array", "items": { "type": "object" } },
                "finding_count": { "type": "integer" },
                "validated_count": { "type": "integer" },
                "report": { "type": "object", "nullable": true }
            }
        }
    })
}

fn build_tags() -> Value {
    json!([
        { "name": "Operations", "description": "SOC alerts/events, safety kill-switch, BAS approvals — runtime control plane." },
        { "name": "Engagement", "description": "Engagements, findings, remediation, reports, copilot, copilot approvals." },
        { "name": "Discovery", "description": "Assets, discovery runs, scans, vuln imports, Prowler imports, cloud inventory & drift, intel feeds, logs (OCSF)." },
        { "name": "Offensive", "description": "BAS techniques & chains, red-team chain compose, attack graph, blast-radius, DAST." },
        { "name": "Pentest", "description": "Combined penetration & vulnerability testing engagements: recon→scan→ingest→BAS→graph-chaining→report with correlated, deduplicated findings (PENTEST-001)." },
        { "name": "Detection", "description": "UEBA, device trust, runtime/falco webhook, hunt query, ML predictive triage." },
        { "name": "Identity", "description": "Auth login/MFA/WebAuthn, SAML, SCIM, IAM users & roles, adaptive auth (RBA)." },
        { "name": "Governance", "description": "Compliance frameworks & evidence, audit search/replay/anchors, GRC push, IR playbooks, DLP." },
        { "name": "AI Audit", "description": "AI-SEC-001 — AI asset inventory / AI-BOM, prompt-injection probing, model-file supply-chain scan, OWASP-LLM/ATLAS mapping, AI governance controls." },
        { "name": "Developer", "description": "OpenAPI, plugins, chaos/risk/RBA configs, push devices, bug-bounty integrations, collab tokens, autonomy, threat-network." }
    ])
}

// ---------------------------------------------------------------------------
// Path catalog
// ---------------------------------------------------------------------------

/// Build the `paths` object. Every route registered in
/// [`crate::router`] has an entry here, grouped by path so that
/// multi-method paths produce a single OpenAPI item with several
/// HTTP-method keys.
fn build_paths() -> Value {
    let mut paths = Map::new();
    for entry in path_entries() {
        let key = entry.path.to_string();
        let mut item = paths.remove(&key).unwrap_or_else(|| json!({}));
        if let Some(obj) = item.as_object_mut() {
            obj.insert(entry.method.to_lowercase(), entry.operation);
        }
        paths.insert(key, item);
    }
    Value::Object(paths)
}

/// A single (method, path, operation) triple emitted by [`path_entries`].
struct PathEntry {
    method: &'static str,
    path: &'static str,
    operation: Value,
}

impl PathEntry {
    fn new(method: &'static str, path: &'static str, operation: Value) -> Self {
        Self {
            method,
            path,
            operation,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn path_entries() -> Vec<PathEntry> {
    let mut v = Vec::new();
    v.extend(operations_routes());
    v.extend(engagement_routes());
    v.extend(discovery_routes());
    v.extend(offensive_routes());
    v.extend(detection_routes());
    v.extend(identity_routes());
    v.extend(governance_routes());
    v.extend(ai_audit_routes());
    v.extend(developer_routes());
    v
}

// ---------------------------------------------------------------------------
// Module: Operations — SOC, safety, kill-switch, approvals.
// ---------------------------------------------------------------------------

fn operations_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/soc/alerts",
            op_list_protected(
                "Operations",
                "listSocAlerts",
                "List SOC alerts visible to the caller.",
                "Returns paginated SOC alerts for the caller's tenant. Served by sx-monolith on \
             port 8080. Requires bearer token (`soc:read`). Supports `limit`/`offset` query \
             params.",
                "SocAlert",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/soc/events",
            op_post_protected(
                "Operations",
                "submitSocEvent",
                "Submit a SOC event.",
                "Accepts a raw SOC event payload (source + arbitrary JSON) for normalisation and \
             alert correlation. Requires bearer token (`soc:write`). Side effect: persists \
             event and may trigger alert generation.",
                "SocEvent",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/safety/kill-switch",
            op_post_protected(
                "Operations",
                "tripKillSwitch",
                "Trip the global safety kill-switch.",
                "Halts all BAS/red-team execution platform-wide. Requires bearer token with \
             `safety:write`. Side effect: pauses scheduled runs and marks safety state as \
             tripped (audit-logged). Idempotent.",
                "KillSwitchRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/bas/approvals",
            op_list_protected(
                "Operations",
                "listBasApprovals",
                "List pending BAS approval requests.",
                "Returns BAS techniques/chains awaiting a quorum approval before execution. \
             Requires bearer token (`bas:approve`).",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/bas/approvals",
            op_post_protected(
                "Operations",
                "recordBasApproval",
                "Record a BAS approval decision.",
                "Submits an approve/deny decision for a pending BAS approval token. Requires \
             bearer token with `bas:approve` and matching MFA assurance level.",
                "BasApprovalRecord",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/copilot/approvals",
            op_list_protected(
                "Operations",
                "listCopilotApprovals",
                "List pending Copilot tool-use approvals.",
                "Returns AI Copilot actions queued for human approval before execution. \
             Requires bearer token (`copilot:approve`).",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/copilot/approvals/{token}/decide",
            op_post_protected_with_params(
                "Operations",
                "decideCopilotApproval",
                "Approve or deny a Copilot approval.",
                "Records the operator's decision for a Copilot tool-use approval. Requires \
             bearer token with `copilot:approve`.",
                "CopilotApprovalDecide",
                "GenericData",
                &[path_string("token")],
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Engagement — engagements, findings, remediation, reports, copilot.
// ---------------------------------------------------------------------------

fn engagement_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/engagements",
            op_list_protected(
                "Engagement",
                "listEngagements",
                "List engagements for the caller's tenant.",
                "Returns paginated engagements. Supports `limit`, `offset`, and `status` query \
             filters. Requires bearer token (`engagement:read`).",
                "Engagement",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("status"),
                ],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements",
            op_post_protected(
                "Engagement",
                "createEngagement",
                "Create a new engagement.",
                "Allocates a new engagement (security-validation effort). Side effect: writes a \
             row to the engagements table and emits an `engagement.created` audit event. \
             Requires bearer token (`engagement:write`).",
                "CreateEngagement",
                "Engagement",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/engagements/{id}",
            op_get_one_protected(
                "Engagement",
                "getEngagement",
                "Get a single engagement by id.",
                "Returns the canonical engagement record. Requires bearer token \
             (`engagement:read`).",
                "Engagement",
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/engagements/{id}",
            op_mutate_protected_with_params(
                "Engagement",
                "updateEngagement",
                "Update engagement metadata.",
                "Patches engagement attributes (name, description, scope set). Requires bearer \
             token (`engagement:write`).",
                "UpdateEngagement",
                "Engagement",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements/{id}/abort",
            op_action_protected(
                "Engagement",
                "abortEngagement",
                "Abort an engagement.",
                "Stops in-flight work and marks the engagement aborted. Side effect: cancels \
             queued BAS/scan tasks. Requires bearer token (`engagement:write`).",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements/{id}/clone",
            op_action_protected(
                "Engagement",
                "cloneEngagement",
                "Clone an engagement.",
                "Creates a new engagement using the source's scope + configuration. Requires \
             bearer token (`engagement:write`).",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements/{id}/complete",
            op_action_protected(
                "Engagement",
                "completeEngagement",
                "Mark an engagement as complete.",
                "Finalises state, freezes scope and emits `engagement.completed` audit event. \
             Requires bearer token (`engagement:write`).",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements/{id}/pause",
            op_action_protected(
                "Engagement",
                "pauseEngagement",
                "Pause an engagement.",
                "Temporarily halts work without aborting. Requires bearer token \
             (`engagement:write`).",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/engagements/{id}/resume",
            op_action_protected(
                "Engagement",
                "resumeEngagement",
                "Resume a paused engagement.",
                "Resumes work for a paused engagement. Requires bearer token \
             (`engagement:write`).",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/findings",
            op_list_protected(
                "Engagement",
                "listFindings",
                "List findings for the caller's tenant.",
                "Returns paginated findings. Supports `limit`, `offset`, `severity`, `status`, \
             `engagement_id` query filters. Requires bearer token (`finding:read`).",
                "Finding",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("severity"),
                    query_string("status"),
                    query_string("engagement_id"),
                ],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/findings/{id}",
            op_get_one_protected(
                "Engagement",
                "getFinding",
                "Get a single finding by id.",
                "Returns the finding with full evidence references. Requires bearer token \
             (`finding:read`).",
                "Finding",
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/findings/{id}/status",
            op_mutate_protected_with_params(
                "Engagement",
                "updateFindingStatus",
                "Update a finding's status.",
                "Transitions status (open → triage → resolved → false-positive). Audit-logged. \
             Requires bearer token (`finding:write`).",
                "FindingStatusUpdate",
                "Finding",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/findings/{id}/remediation",
            op_mutate_protected_with_params(
                "Engagement",
                "linkFindingRemediation",
                "Link a finding to a remediation advisory.",
                "Associates a finding with an advisory (PR, ticket, runbook). Requires bearer \
             token (`finding:write`).",
                "FindingRemediationLink",
                "Finding",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/findings/{id}/remediation",
            op_delete_with_params(
                "Engagement",
                "unlinkFindingRemediation",
                "Unlink a finding from its remediation advisory.",
                "Removes the advisory association. Audit-logged. Requires bearer token \
             (`finding:write`).",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/findings/bulk-update",
            op_post_protected(
                "Engagement",
                "bulkUpdateFindings",
                "Bulk-update finding statuses.",
                "Atomically updates status for a list of finding IDs. Requires bearer token \
             (`finding:write`). Returns per-id outcomes.",
                "FindingBulkUpdate",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/findings/export",
            op_list_protected(
                "Engagement",
                "exportFindings",
                "Export findings as CSV/JSON.",
                "Streams the findings export for the caller's tenant. Supports `format=csv|json` \
             query param. Requires bearer token (`finding:read`).",
                "Finding",
                &[query_string("format"), query_string("status")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/copilot/chat",
            op_post_protected(
                "Engagement",
                "copilotChat",
                "Send a single-turn prompt to the AI Copilot.",
                "Returns a model reply. Subject to per-tenant rate limits and an optional \
             approval step for high-risk tool calls. Requires bearer token (`copilot:use`).",
                "CopilotChatRequest",
                "CopilotChatResponse",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/reports",
            op_list_protected(
                "Engagement",
                "listReports",
                "List rendered engagement reports.",
                "Returns metadata for all reports the caller can read. Requires bearer token \
             (`report:read`).",
                "ReportSummaryView",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("engagement_id"),
                ],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/reports/render",
            op_post_protected(
                "Engagement",
                "renderReport",
                "Render an engagement report.",
                "Synthesises an executive/technical report (PDF/HTML/JSON/MD) for an engagement. \
             Side effect: writes the artifact to object storage. Requires bearer token \
             (`report:write`).",
                "ReportRenderRequest",
                "ReportSummaryView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/reports/diff",
            op_post_protected(
                "Engagement",
                "diffReports",
                "Diff two reports.",
                "Computes a structured diff between two report snapshots. Requires bearer token \
             (`report:read`).",
                "ReportDiffRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/reports/branding",
            op_list_protected(
                "Engagement",
                "getReportBranding",
                "Get the caller tenant's report branding.",
                "Returns the per-tenant white-label branding (logo, primary colour, cover/footer \
             Markdown) applied to rendered reports. Requires bearer token (`report:read`).",
                "BrandingView",
                &[],
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/reports/branding",
            op_post_protected(
                "Engagement",
                "setReportBranding",
                "Set the caller tenant's report branding.",
                "Replaces the per-tenant white-label branding used by the report renderers \
             (MSSP white-label, P2-002). Audit-logged. Requires bearer token (`report:write`).",
                "SetBrandingRequest",
                "BrandingView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/reports/comprehensive",
            op_list_protected(
                "Engagement",
                "getComprehensiveReport",
                "Generate the comprehensive cross-module report.",
                "Aggregates findings posture + compliance control coverage across modules and \
             returns a server-rendered executive report (structured fields + Markdown). \
             Requires bearer token (`report:read`).",
                "ComprehensiveReportView",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/reports/schedules",
            op_list_protected(
                "Engagement",
                "listReportSchedules",
                "List scheduled report distributions.",
                "Returns the tenant's cron-scheduled report deliveries. Requires bearer token \
             (`report:read`).",
                "ReportScheduleView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/reports/schedules",
            op_post_protected(
                "Engagement",
                "createReportSchedule",
                "Register a scheduled report distribution.",
                "Registers a cron-scheduled report render + delivery (P2-001). Requires bearer \
             token (`report:write`).",
                "CreateReportScheduleRequest",
                "ReportScheduleView",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/reports/schedules/{id}",
            op_post_protected(
                "Engagement",
                "deleteReportSchedule",
                "Disable a scheduled report distribution.",
                "Disables (soft-deletes) a report schedule so the tick loop skips it. Requires \
             bearer token (`report:write`).",
                "GenericData",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/remediation/advisories",
            op_post_protected(
                "Engagement",
                "generateRemediationAdvisory",
                "Generate a remediation advisory for a finding.",
                "Runs the advisory generator (templated + AI-assisted). Requires bearer token \
             (`remediation:write`).",
                "RemediationAdvisoryRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/remediation/outcomes/metrics",
            op_list_protected(
                "Engagement",
                "remediationOutcomeMetrics",
                "Remediation outcome metrics.",
                "Aggregated counts of resolved/regressed findings over time. Requires bearer \
             token (`remediation:read`).",
                "RemediationOutcomeMetrics",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/remediation/outcomes/regressions",
            op_list_protected(
                "Engagement",
                "remediationOutcomeRegressions",
                "List remediation regressions.",
                "Findings that re-opened after a successful remediation. Requires bearer token \
             (`remediation:read`).",
                "Finding",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/risk/calculate",
            op_post_protected(
                "Engagement",
                "calculateRisk",
                "Compute a composite risk score.",
                "Combines CVSS, EPSS, exposure and asset criticality into a composite score. \
             Stateless. Requires bearer token (`risk:read`).",
                "RiskCalculateRequest",
                "RiskCalculateResponse",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/risk/engagement/{engagement_id}",
            op_mutate_protected_with_params(
                "Engagement",
                "calculateRiskForEngagement",
                "Compute risk for an engagement.",
                "Aggregates risk across all findings in an engagement and persists the result. \
             Requires bearer token (`risk:read`).",
                "GenericRequest",
                "RiskCalculateResponse",
                &[path_string("engagement_id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/twin/engagement/{engagement_id}",
            op_get_one_with_params(
                "Engagement",
                "getDigitalTwin",
                "Get the digital-twin snapshot for an engagement.",
                "Returns the latest digital-twin graph (assets/services/edges) for the \
             engagement. Requires bearer token (`twin:read`).",
                "GenericData",
                &[path_string("engagement_id")],
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Discovery — assets, scans, vuln, prowler, cloud, intel, logs.
// ---------------------------------------------------------------------------

fn discovery_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/assets",
            op_list_protected(
                "Discovery",
                "listAssets",
                "List assets in the caller's tenant.",
                "Returns paginated assets. Supports `limit`, `offset`, `kind`, `tag` query \
             filters. Requires bearer token (`asset:read`).",
                "Asset",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("kind"),
                    query_string("tag"),
                ],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/assets",
            op_post_protected(
                "Discovery",
                "createAsset",
                "Create a single asset.",
                "Inserts a new asset record. Requires bearer token (`asset:write`).",
                "CreateAsset",
                "Asset",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/assets/{id}",
            op_get_one_protected(
                "Discovery",
                "getAsset",
                "Get a single asset by id.",
                "Returns the canonical asset record. Requires bearer token (`asset:read`).",
                "Asset",
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/assets/{id}",
            op_mutate_protected_with_params(
                "Discovery",
                "updateAsset",
                "Update an asset.",
                "Patches asset attributes. Requires bearer token (`asset:write`).",
                "CreateAsset",
                "Asset",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/assets/{id}",
            op_delete_with_params(
                "Discovery",
                "deleteAsset",
                "Delete an asset.",
                "Soft-deletes the asset. Requires bearer token (`asset:write`).",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/assets/bulk-import",
            op_post_protected(
                "Discovery",
                "bulkImportAssets",
                "Bulk-import assets.",
                "Inserts up to N assets in a single batch. Returns per-row outcomes. Requires \
             bearer token (`asset:write`).",
                "BulkAssetImport",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/discovery/runs",
            op_post_protected(
                "Discovery",
                "runDiscovery",
                "Start a discovery run.",
                "Enqueues an active discovery scan against a target. Side effect: spawns a \
             scanner worker, emits `discovery.run.started`. Requires bearer token \
             (`discovery:write`).",
                "DiscoveryRunRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/scans",
            op_list_protected(
                "Discovery",
                "listScans",
                "List scans for the caller's tenant.",
                "Returns paginated scan records. Requires bearer token (`scan:read`).",
                "GenericData",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/scans/http-headers",
            op_post_protected(
                "Discovery",
                "runHttpHeadersScan",
                "Run an HTTP-headers scan.",
                "Fetches a URL and audits HTTP security headers (CSP, HSTS, X-Content-Type, …). \
             Requires bearer token (`scan:write`).",
                "ScanHttpHeadersRequest",
                "GenericData",
            ),
        ),
        // TOP5-#3-P2-SARIF-API — SARIF v2.1.0 export of a single scan
        // record. Read-only; same `scans:read` permission as the JSON
        // list endpoint. Response body is `application/sarif+json`, not
        // `application/json` — set in the controller via the explicit
        // `Content-Type` header on the response builder.
        PathEntry::new(
            "GET",
            "/v1/scans/{id}.sarif",
            op_get_one_with_params(
                "Discovery",
                "getScanSarif",
                "Export a scan as a SARIF v2.1.0 envelope.",
                "Returns the stored HTTP-headers scan identified by `{id}` as a SARIF v2.1.0 \
             log (Content-Type: `application/sarif+json`). Suitable for direct ingestion \
             by GitHub Code Scanning, GitLab Security Dashboard, and other enterprise SOC \
             pipelines. Requires bearer token (`scans:read`).",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/discovery/dast/scan",
            op_post_protected(
                "Discovery",
                "runDastScan",
                "Run an API DAST scan.",
                "Crawls and fuzzes a target API (driven by an OpenAPI spec when supplied). \
             Requires bearer token (`scan:write`).",
                "ApiDastScanRequest",
                "ApiDastScanResultView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/discovery/dast/scans",
            op_list_protected(
                "Discovery",
                "listDastScans",
                "List API DAST scan results.",
                "Returns historical DAST scan results. Requires bearer token (`scan:read`).",
                "ApiDastScanResultView",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/discovery/prowler/import",
            op_post_protected(
                "Discovery",
                "importProwler",
                "Import Prowler scan findings.",
                "Ingests AWS/GCP/Azure findings from a Prowler JSON export and normalises into \
             SentinelX findings. Requires bearer token (`finding:write`).",
                "ProwlerImportRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/vuln/import",
            op_post_protected(
                "Discovery",
                "importVulnerabilities",
                "Import vulnerability scanner output.",
                "Accepts CSV/JSON from Nessus, Qualys, Trivy, etc. and normalises into \
             SentinelX findings. Requires bearer token (`finding:write`).",
                "VulnImportRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/vuln/imports",
            op_list_protected(
                "Discovery",
                "listVulnImports",
                "List historical vulnerability imports.",
                "Returns the import history (timestamps, sources, counts). Requires bearer token \
             (`finding:read`).",
                "GenericData",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/cloud/inventory",
            op_list_protected(
                "Discovery",
                "listCloudInventoryGet",
                "List cached cloud inventory.",
                "Returns the latest known cloud resources (EC2, S3, RDS, GCS, ARM, …) for the \
             tenant. Requires bearer token (`cloud:read`).",
                "GenericData",
                &[query_string("provider"), query_string("region")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/cloud/inventory",
            op_post_protected(
                "Discovery",
                "fetchCloudInventory",
                "Refresh cloud inventory.",
                "Performs an on-demand inventory pull against the configured providers. Side \
             effect: persists fresh inventory rows. Requires bearer token (`cloud:write`).",
                "CloudInventoryRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/cloud/drift/scan",
            op_post_protected(
                "Discovery",
                "scanCloudDrift",
                "Scan cloud configuration drift.",
                "Compares current cloud inventory against a stored baseline. Returns drift \
             findings. Requires bearer token (`cloud:write`).",
                "CloudDriftScanRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/cloud/drift/findings",
            op_list_protected(
                "Discovery",
                "listCloudDriftFindings",
                "List cloud drift findings.",
                "Returns paginated drift findings. Requires bearer token (`cloud:read`).",
                "GenericData",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/cloud/drift/baselines",
            op_list_protected(
                "Discovery",
                "listCloudDriftBaselines",
                "List cloud drift baselines.",
                "Returns metadata for stored cloud baselines. Requires bearer token \
             (`cloud:read`).",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/cloud/drift/baselines",
            op_post_protected(
                "Discovery",
                "uploadCloudDriftBaseline",
                "Upload a new cloud drift baseline.",
                "Stores a snapshot of approved cloud resource state for later drift comparison. \
             Requires bearer token (`cloud:write`).",
                "BaselineUpload",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/intel/feeds",
            op_list_protected(
                "Discovery",
                "listIntelFeeds",
                "List threat intel feed status.",
                "Returns configured threat-intel feeds and their last successful pull \
             timestamps. Requires bearer token (`intel:read`).",
                "FeedStatusView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/intel/check",
            op_post_protected(
                "Discovery",
                "checkIndicator",
                "Check an IOC against all feeds.",
                "Looks up an indicator (IP/domain/URL/hash) in cached feeds and returns matches. \
             Requires bearer token (`intel:read`).",
                "IntelCheckRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/logs",
            op_list_protected(
                "Discovery",
                "listLogs",
                "List ingested log envelopes.",
                "Returns paginated OCSF log envelopes for the caller's tenant. Supports \
             `source`, `since`, `until` query params. Requires bearer token (`log:read`).",
                "GenericData",
                &[
                    query_int("limit"),
                    query_string("source"),
                    query_string("since"),
                    query_string("until"),
                ],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/logs/ingest",
            op_post_protected(
                "Discovery",
                "ingestLogs",
                "Ingest a batch of OCSF log events.",
                "Accepts a batch of OCSF events (e.g. CloudTrail), validates, persists, and \
             routes to downstream UEBA / hunt. Requires bearer token (`log:write`).",
                "LogIngestRequest",
                "GenericData",
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Offensive — BAS, BAS chains, red-team, attack graph, blast-radius.
// ---------------------------------------------------------------------------

fn offensive_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "POST",
            "/v1/bas/run",
            op_post_protected(
                "Offensive",
                "runBas",
                "Run a BAS technique.",
                "Executes a single BAS technique against an engagement target. May require an \
             approval token for high-risk techniques. Side effect: produces evidence rows. \
             Requires bearer token (`bas:run`).",
                "BasRunRequest",
                "BasRunResponse",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/bas/runs",
            op_list_protected(
                "Offensive",
                "listBasRuns",
                "List BAS simulation runs.",
                "Returns paginated BAS run history. Requires bearer token (`bas:read`).",
                "GenericData",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("engagement_id"),
                ],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/bas/chains",
            op_list_protected(
                "Offensive",
                "listBasChains",
                "List multi-step BAS chains.",
                "Returns multi-step BAS attack chains (kill-chain compositions). Requires \
             bearer token (`bas:read`).",
                "BasChainView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/bas/chains/{id}/run",
            op_mutate_protected_with_params(
                "Offensive",
                "runBasChain",
                "Start a multi-step BAS chain run.",
                "Enqueues a BAS chain for execution. Side effect: spawns chain runner, may \
             require quorum approvals between steps. Requires bearer token (`bas:run`).",
                "BasChainRunRequest",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/bas/chains/runs/{id}",
            op_get_one_with_params(
                "Offensive",
                "getBasChainRun",
                "Get a BAS chain run.",
                "Returns the full run state, per-step outcomes and evidence references. \
             Requires bearer token (`bas:read`).",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/redteam/chain",
            op_post_protected(
                "Offensive",
                "composeRedTeamChain",
                "Compose a red-team chain.",
                "Asks the planner to synthesise a multi-step red-team chain from objectives. \
             Requires bearer token (`redteam:write`).",
                "RedTeamChainRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/graph/attack-paths",
            op_post_protected(
                "Offensive",
                "searchAttackPaths",
                "Search attack-graph paths.",
                "Runs a constrained path search through the asset/identity/permission graph. \
             Requires bearer token (`graph:read`).",
                "AttackPathRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/cloud/blast-radius",
            op_post_protected(
                "Offensive",
                "computeBlastRadius",
                "Compute blast radius for an asset.",
                "Returns assets reachable from a compromised seed within `max_depth` hops in \
             the cloud/identity graph. Requires bearer token (`graph:read`).",
                "BlastRadiusRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/pentest/runs",
            op_post_protected(
                "Pentest",
                "runPentest",
                "Launch a combined pentest engagement.",
                "Runs the ordered phases recon → enumeration → vuln-scan → DAST → \
             code/cloud → credentialed-ingest → BAS validation → graph chaining → report \
             as one engagement, correlating and deduplicating findings across every \
             scanner. Side effect: produces evidence rows and a rendered report. \
             Requires bearer token (`pentest:run`).",
                "PentestRunRequest",
                "PentestRunView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/pentest/runs",
            op_list_protected(
                "Pentest",
                "listPentestRuns",
                "List combined pentest runs.",
                "Returns recent pentest runs for the caller's tenant, newest first. \
             Requires bearer token (`pentest:read`).",
                "PentestRunView",
                &[query_int("limit")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/pentest/runs/{id}",
            op_get_one_with_params(
                "Pentest",
                "getPentestRun",
                "Get a combined pentest run.",
                "Returns the full run state: per-phase outcomes, correlated findings, \
             attack narratives, and the assembled report summary. Requires bearer token \
             (`pentest:read`).",
                "PentestRunView",
                &[path_string("id")],
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Detection — UEBA, device-trust, runtime/falco, hunt, ML.
// ---------------------------------------------------------------------------

fn detection_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/ueba/anomalies",
            op_list_protected(
                "Detection",
                "listUebaAnomalies",
                "List UEBA anomalies.",
                "Returns scored user/entity behaviour anomalies. Requires bearer token \
             (`ueba:read`).",
                "UebaAnomalyView",
                &[
                    query_int("limit"),
                    query_int("offset"),
                    query_string("user_id"),
                ],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/ueba/baselines/{user_id}",
            op_get_one_with_params(
                "Detection",
                "getUebaBaseline",
                "Get a user's UEBA baseline.",
                "Returns the rolling behavioural baseline for one user. Requires bearer token \
             (`ueba:read`).",
                "GenericData",
                &[path_string("user_id")],
            ),
        ),
        // HIGH-010 — UEBA frozen-baseline mode (anti-poisoning).
        PathEntry::new(
            "POST",
            "/v1/admin/ueba/baseline/{user_id}/freeze",
            op_post_protected_with_params(
                "Detection",
                "freezeUebaBaseline",
                "Engage Frozen mode for a user's UEBA baseline.",
                "Captures the current live baseline as a snapshot, blocks future \
             writes against the live baseline, and routes subsequent scoring \
             through the snapshot. Anti-poisoning lever for active incidents. \
             Requires bearer token (`admin:users`).",
                "GenericData",
                "GenericData",
                &[path_string("user_id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/ueba/baseline/{user_id}/unfreeze",
            op_post_protected_with_params(
                "Detection",
                "unfreezeUebaBaseline",
                "Release Frozen mode and run drift detection.",
                "Flips the baseline back to Active and runs the drift detector \
             (> 3σ vs snapshot) routing findings to SOC. Requires bearer \
             token (`admin:users`).",
                "GenericData",
                "GenericData",
                &[path_string("user_id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/ueba/baseline/{user_id}/snapshot",
            op_get_one_with_params(
                "Detection",
                "getUebaBaselineSnapshot",
                "Get the current state + (if Frozen) snapshot for a user.",
                "Returns the lifecycle state (learning / active / frozen) and the \
             captured snapshot counters when state == frozen. Requires bearer \
             token (`admin:users`).",
                "GenericData",
                &[path_string("user_id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/device-trust/policy",
            op_get_one_protected(
                "Detection",
                "getDeviceTrustPolicy",
                "Get the device-trust policy.",
                "Returns the current device-trust policy for the caller's tenant. Requires \
             bearer token (`device-trust:read`).",
                "DeviceTrustPolicy",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/device-trust/policy",
            op_post_protected(
                "Detection",
                "putDeviceTrustPolicy",
                "Replace the device-trust policy.",
                "Atomically replaces the active policy. Audit-logged. Requires bearer token \
             (`device-trust:write`).",
                "DeviceTrustPolicy",
                "DeviceTrustPolicy",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/device-trust/sessions",
            op_list_protected(
                "Detection",
                "listDeviceTrustSessions",
                "List recent device-trust evaluation sessions.",
                "Returns each session evaluation with policy verdict. Requires bearer token \
             (`device-trust:read`).",
                "GenericData",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/runtime/falco/alerts",
            op_public_post(
                "Detection",
                "ingestFalcoAlerts",
                "Ingest a Falco runtime alert (webhook).",
                "Accepts a Falco alert JSON document. **Public** webhook endpoint — \
             authenticated by a shared signing secret in the request header, not a bearer \
             token. Side effect: persists alert and may trigger downstream SOC events.",
                "RuntimeFalcoAlert",
                "GenericData",
            ),
        ),
        // HIGH-006 — Falco rule allow/deny admin surface (per tenant).
        PathEntry::new(
            "GET",
            "/v1/admin/runtime/falco/overrides",
            op_list_protected(
                "Detection",
                "listFalcoOverrides",
                "List per-tenant Falco rule overrides.",
                "Returns every override row for the caller's tenant. Requires bearer token \
             (`runtime:read`).",
                "FalcoOverrideView",
                &[],
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/admin/runtime/falco/overrides",
            op_post_protected(
                "Detection",
                "putFalcoOverride",
                "Upsert a Falco rule override.",
                "Idempotent on `(rule_name, subkey)`. Action must be `allow`, `deny`, \
             `escalate`, or `downgrade`. Every mutation is audit-logged. Requires bearer \
             token (`runtime:write`).",
                "PutFalcoOverrideRequest",
                "FalcoOverrideView",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/admin/runtime/falco/overrides",
            op_post_protected(
                "Detection",
                "deleteFalcoOverride",
                "Delete a Falco rule override.",
                "Idempotent — returns `removed: false` when the row was absent. The key \
             travels in the JSON body because the wildcard subkey `*` does not round-trip \
             cleanly through a URL path. Requires bearer token (`runtime:write`).",
                "DeleteFalcoOverrideRequest",
                "DeleteFalcoOverrideResponse",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/hunt/query",
            op_post_protected(
                "Detection",
                "huntQuery",
                "Run a KQL-style hunt query.",
                "Executes an ad-hoc detection query against the log/event store and returns \
             matching records. Requires bearer token (`hunt:read`).",
                "HuntQueryRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/ml/predict/finding",
            op_post_protected(
                "Detection",
                "predictFinding",
                "Predict next-likely finding (predictive engine).",
                "Returns predictive risk scores from the trained model. Requires bearer token \
             (`ml:read`).",
                "PredictiveRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/ml/predict/triage",
            op_post_protected(
                "Detection",
                "predictTriage",
                "ML-assisted finding triage.",
                "Returns model-suggested severity / disposition for a finding. Requires bearer \
             token (`ml:read`).",
                "MlTriageRequest",
                "GenericData",
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Identity — auth, MFA, WebAuthn, SAML, SCIM, IAM, RBA.
// ---------------------------------------------------------------------------

fn identity_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "POST",
            "/v1/auth/login",
            op_public_post(
                "Identity",
                "authLogin",
                "Exchange credentials for an access + refresh token.",
                "Authenticates with email + password. Returns a JWT pair. **Public** endpoint. \
             Subject to brute-force protection and RBA risk scoring.",
                "LoginRequest",
                "TokenView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/logout",
            op_post_protected(
                "Identity",
                "authLogout",
                "Revoke the current session.",
                "Invalidates the bearer token and any refresh token bound to the session. \
             Requires bearer token.",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/refresh",
            op_public_post(
                "Identity",
                "authRefresh",
                "Trade a refresh token for a fresh access token.",
                "Issues a new access token from a still-valid refresh token. **Public** \
             endpoint (auth is the refresh token itself).",
                "RefreshRequest",
                "TokenView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/oidc/exchange",
            op_public_post(
                "Identity",
                "authOidcExchange",
                "Exchange an OIDC authorisation code for tokens.",
                "Completes the OIDC code flow against a configured upstream IDP. **Public** \
             endpoint.",
                "OidcExchangeRequest",
                "TokenView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/signup",
            op_public_post(
                "Identity",
                "authSignup",
                "Customer sign-up (self-service).",
                "Creates a tenant and admin user. Sends a verification email. **Public** \
             endpoint.",
                "SignupRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/verify-email",
            op_public_post(
                "Identity",
                "authVerifyEmail",
                "Verify a sign-up email-confirmation token.",
                "Marks the email verified and unlocks the account. **Public** endpoint.",
                "VerifyEmailRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/forgot-password",
            op_public_post(
                "Identity",
                "authForgotPassword",
                "Trigger a password-reset email.",
                "Always returns 200 to avoid account enumeration. **Public** endpoint.",
                "ForgotPasswordRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/reset-password",
            op_public_post(
                "Identity",
                "authResetPassword",
                "Reset a password using a reset token.",
                "Validates the token and sets a new password. **Public** endpoint.",
                "ResetPasswordRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/auth/saml/metadata",
            op_public_get(
                "Identity",
                "samlMetadata",
                "SAML 2.0 SP metadata.",
                "Returns the service-provider metadata document used by IdPs during \
             federation onboarding. **Public** endpoint.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/saml/acs",
            op_public_post(
                "Identity",
                "samlAcs",
                "SAML 2.0 assertion consumer service.",
                "Handles a signed SAML response from the IdP and starts an authenticated \
             session. **Public** endpoint (authenticated by signed SAML assertion).",
                "GenericRequest",
                "TokenView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/auth/saml/logout",
            op_public_get(
                "Identity",
                "samlSlo",
                "SAML 2.0 single-logout.",
                "Handles a single-logout request from the IdP. **Public** endpoint.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/mfa/webauthn/register/start",
            op_post_protected(
                "Identity",
                "webauthnRegisterStart",
                "Start WebAuthn credential registration.",
                "Returns the PublicKey-Credential-CreationOptions challenge. Requires bearer \
             token.",
                "WebAuthnRegisterStartRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/mfa/webauthn/register/finish",
            op_post_protected(
                "Identity",
                "webauthnRegisterFinish",
                "Finish WebAuthn credential registration.",
                "Validates the attestation and persists the credential. Requires bearer token.",
                "WebAuthnFinishRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/mfa/webauthn/login/start",
            op_public_post(
                "Identity",
                "webauthnLoginStart",
                "Start WebAuthn assertion.",
                "Returns the PublicKey-Credential-RequestOptions challenge. **Public** endpoint \
             (used during login flow).",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/auth/mfa/webauthn/login/finish",
            op_public_post(
                "Identity",
                "webauthnLoginFinish",
                "Finish WebAuthn assertion.",
                "Validates the assertion and upgrades the session to a fully authenticated \
             token. **Public** endpoint.",
                "WebAuthnFinishRequest",
                "TokenView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/mfa/enroll",
            op_post_protected(
                "Identity",
                "mfaEnroll",
                "Begin MFA enrollment.",
                "Issues a TOTP secret or WebAuthn challenge. Requires bearer token.",
                "MfaEnrollRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/mfa/verify",
            op_post_protected(
                "Identity",
                "mfaVerify",
                "Verify MFA code.",
                "Completes MFA enrollment or step-up by verifying a TOTP/SMS code. Requires \
             bearer token.",
                "MfaVerifyRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/mfa/disable",
            op_post_protected(
                "Identity",
                "mfaDisable",
                "Disable MFA for the current user.",
                "Removes all MFA factors. Audit-logged. Requires bearer token.",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/mfa/status",
            op_get_one_protected(
                "Identity",
                "mfaStatus",
                "Get current MFA status.",
                "Returns whether MFA is enabled for the caller and which factors are \
             registered. Requires bearer token.",
                "MfaStatusView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/users",
            op_list_protected(
                "Identity",
                "listAdminUsers",
                "List users in the caller's tenant.",
                "Returns paginated user records. Requires bearer token (`admin:users`).",
                "CreateUserResponse",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/users",
            op_post_protected(
                "Identity",
                "createAdminUser",
                "Provision a new user.",
                "Creates a user with role assignments. Requires bearer token (`admin:users`).",
                "CreateUserRequest",
                "CreateUserResponse",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/users/{user_id}/roles",
            op_mutate_protected_with_params(
                "Identity",
                "assignRoleToUser",
                "Assign a role to a user.",
                "Adds a role to the target user's role set. Requires bearer token \
             (`admin:roles`).",
                "RoleAssignRequest",
                "GenericData",
                &[path_string("user_id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/roles",
            op_list_protected(
                "Identity",
                "listAdminRoles",
                "List roles defined in the caller's tenant.",
                "Returns paginated role records. Requires bearer token (`admin:roles`).",
                "Role",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/roles",
            op_post_protected(
                "Identity",
                "createAdminRole",
                "Create a new role in the caller's tenant.",
                "Inserts a role with the supplied permissions. Requires bearer token \
             (`admin:roles`).",
                "CreateRoleRequest",
                "Role",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/admin/roles/{role_id}",
            op_delete_with_params(
                "Identity",
                "deleteAdminRole",
                "Delete a role.",
                "Removes the role and unassigns it from all users. Requires bearer token \
             (`admin:roles`).",
                &[path_string("role_id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/tenants",
            op_list_protected(
                "Identity",
                "listTenants",
                "List tenants (super-admin).",
                "Returns all tenants. Requires bearer token (`admin:tenants`).",
                "TenantView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/tenants",
            op_post_protected(
                "Identity",
                "createTenant",
                "Create a tenant (super-admin).",
                "Provisions a new tenant. Requires bearer token (`admin:tenants`).",
                "CreateTenantRequest",
                "TenantView",
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/admin/tenants/{id}",
            op_mutate_protected_with_params(
                "Identity",
                "updateTenant",
                "Update a tenant (super-admin).",
                "Patches tenant attributes. Requires bearer token (`admin:tenants`).",
                "UpdateTenantRequest",
                "TenantView",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/admin/tenants/{id}",
            op_delete_with_params(
                "Identity",
                "deleteTenant",
                "Delete a tenant (super-admin).",
                "Soft-deletes the tenant. Requires bearer token (`admin:tenants`).",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/tenants/me",
            op_get_one_protected(
                "Identity",
                "getMyTenant",
                "Get the caller's tenant.",
                "Returns the tenant metadata for the calling JWT. Requires bearer token.",
                "TenantView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/scim/users",
            op_list_protected(
                "Identity",
                "scimAdminListUsers",
                "List SCIM users (admin view).",
                "Returns SCIM-provisioned users in the caller's tenant. Requires bearer token \
             (`admin:users`).",
                "ScimUser",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/scim/tokens",
            op_list_protected(
                "Identity",
                "scimAdminListTokens",
                "List SCIM provisioning tokens.",
                "Returns metadata for issued SCIM tokens (no plaintext secrets). Requires \
             bearer token (`admin:users`).",
                "ScimToken",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/scim/tokens",
            op_post_protected(
                "Identity",
                "scimAdminCreateToken",
                "Create a SCIM provisioning token.",
                "Returns the new token plaintext exactly once. Audit-logged. Requires bearer \
             token (`admin:users`).",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/admin/scim/tokens/{id}",
            op_delete_with_params(
                "Identity",
                "scimAdminRevokeToken",
                "Revoke a SCIM provisioning token.",
                "Permanently invalidates the token. Requires bearer token (`admin:users`).",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/admin/scim/tokens/{id}/rotate",
            op_mutate_protected_with_params(
                "Identity",
                "scimAdminRotateToken",
                "Rotate a SCIM provisioning token (MED-005).",
                "Mints a new token inheriting the original's scopes and TTL; old token enters a \
             7-day grace window during which both authenticate. Returns the new plaintext \
             exactly once. Requires bearer token (`admin:users`).",
                "GenericRequest",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        // CRIT-003 — per-tenant DEK rotation admin endpoints (Identity
        // tag — these are operator-only admin surfaces).
        PathEntry::new(
            "POST",
            "/v1/admin/secrets/rotate-dek",
            op_post_protected(
                "Identity",
                "rotateTenantDek",
                "Rotate a tenant's DEK (CRIT-003).",
                "Triggers (or resumes) a per-tenant DEK rotation. Re-encrypts every \
             tenant-scoped row from the old DEK to the new one in batched, \
             checkpointed work. Each batch + lifecycle transition emits an audit \
             event. Requires `admin:secrets`.",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/admin/secrets/rotation-progress",
            op_list_protected(
                "Identity",
                "tenantDekRotationProgress",
                "Read the latest DEK rotation checkpoint for a tenant (CRIT-003).",
                "Returns `(target_dek_version, status, processed_rows, total_rows, \
             timestamps, redacted_error)`. Requires `admin:secrets`.",
                "GenericData",
                &[query_string("tenant_id")],
            ),
        ),
        // MED-003 — per-tenant outbound webhook signing-key rotation.
        PathEntry::new(
            "POST",
            "/v1/admin/webhooks/keys/rotate",
            op_post_protected(
                "Identity",
                "rotateTenantWebhookKey",
                "Force-rotate a tenant's outbound webhook signing key (MED-003).",
                "Mints a fresh `kid` for the tenant's outbound webhook HMAC chain \
             and schedules the previous active key for retirement at \
             `now + grace_window` (7 days by default). Both kids remain valid \
             throughout the grace window so receivers can swap atomically. \
             Requires `admin:webhooks`.",
                "GenericRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/scim/v2/Users",
            op_list_protected(
                "Identity",
                "scimListUsers",
                "SCIM 2.0 — list users.",
                "Standards-compliant SCIM 2.0 endpoint. Authenticated by SCIM bearer token. \
             Supports `filter`, `startIndex`, `count` query params.",
                "ScimUser",
                &[
                    query_string("filter"),
                    query_int("startIndex"),
                    query_int("count"),
                ],
            ),
        ),
        PathEntry::new(
            "POST",
            "/scim/v2/Users",
            op_post_protected(
                "Identity",
                "scimCreateUser",
                "SCIM 2.0 — create user.",
                "Creates a SCIM user. Authenticated by SCIM bearer token.",
                "ScimUser",
                "ScimUser",
            ),
        ),
        PathEntry::new(
            "GET",
            "/scim/v2/Users/{id}",
            op_get_one_with_params(
                "Identity",
                "scimGetUser",
                "SCIM 2.0 — get user by id.",
                "Returns a SCIM user. Authenticated by SCIM bearer token.",
                "ScimUser",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "PUT",
            "/scim/v2/Users/{id}",
            op_mutate_protected_with_params(
                "Identity",
                "scimReplaceUser",
                "SCIM 2.0 — replace user.",
                "Replaces a SCIM user resource (PUT semantics). Authenticated by SCIM bearer \
             token.",
                "ScimUser",
                "ScimUser",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/scim/v2/Users/{id}",
            op_delete_with_params(
                "Identity",
                "scimDeleteUser",
                "SCIM 2.0 — delete user.",
                "Deletes a SCIM user. Authenticated by SCIM bearer token.",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/scim/v2/Groups",
            op_list_protected(
                "Identity",
                "scimListGroups",
                "SCIM 2.0 — list groups.",
                "Standards-compliant SCIM 2.0 endpoint. Authenticated by SCIM bearer token.",
                "ScimGroup",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/scim/v2/Groups",
            op_post_protected(
                "Identity",
                "scimCreateGroup",
                "SCIM 2.0 — create group.",
                "Creates a SCIM group. Authenticated by SCIM bearer token.",
                "ScimGroup",
                "ScimGroup",
            ),
        ),
        PathEntry::new(
            "GET",
            "/scim/v2/Groups/{id}",
            op_get_one_with_params(
                "Identity",
                "scimGetGroup",
                "SCIM 2.0 — get group by id.",
                "Returns a SCIM group. Authenticated by SCIM bearer token.",
                "ScimGroup",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/rba/config",
            op_get_one_protected(
                "Identity",
                "getRbaConfig",
                "Get the risk-based-auth (RBA) configuration.",
                "Returns the tenant's adaptive-auth thresholds. Requires bearer token \
             (`rba:read`).",
                "RbaConfig",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/rba/config",
            op_post_protected(
                "Identity",
                "putRbaConfig",
                "Update the risk-based-auth (RBA) configuration.",
                "Replaces the adaptive-auth thresholds. Requires bearer token (`rba:write`).",
                "RbaConfig",
                "RbaConfig",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/rba/decisions",
            op_list_protected(
                "Identity",
                "listRbaDecisions",
                "List recent adaptive-auth decisions.",
                "Returns auth attempts with their risk score and decision (allow/step-up/deny). \
             Requires bearer token (`rba:read`).",
                "GenericData",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/rba/users/{user_id}/devices",
            op_get_one_protected(
                "Identity",
                "listRbaKnownDevices",
                "List enrolled device fingerprints for a user (HIGH-001).",
                "Returns every device fingerprint the RBA device-fp signal has observed \
             for `user_id` within the caller's tenant — known and revoked alike. \
             Powers the dashboard's 'my devices' view. Requires `admin:users`.",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/rba/users/{user_id}/devices/{fp_hash}",
            op_get_one_protected(
                "Identity",
                "revokeRbaKnownDevice",
                "Revoke a single enrolled device fingerprint (HIGH-001).",
                "Locks the fingerprint to the maximum device-fp sub-score on future logins. \
             Idempotent. Requires `admin:users`.",
                "GenericData",
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Governance — compliance, evidence, audit, GRC, IR, DLP.
// ---------------------------------------------------------------------------

fn governance_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/compliance/frameworks/{framework}",
            op_get_one_with_params(
                "Governance",
                "listFrameworkControls",
                "List controls for a compliance framework.",
                "Returns the SentinelX-mapped controls for a framework (e.g. `soc2`, `iso27001`, \
             `pci-dss`, `hipaa`, `nist-csf`). Requires bearer token (`compliance:read`).",
                "GenericData",
                &[path_string("framework")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/compliance/map",
            op_post_protected(
                "Governance",
                "mapFindingToControls",
                "Map a finding to compliance controls.",
                "Records that a finding satisfies/violates a set of controls. Requires bearer \
             token (`compliance:write`).",
                "ComplianceMapRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/compliance/evidence/collect",
            op_post_protected(
                "Governance",
                "collectComplianceEvidence",
                "Trigger evidence collection for a framework.",
                "Asynchronously bundles all current evidence for a framework into a downloadable \
             archive. Requires bearer token (`compliance:write`).",
                "ComplianceEvidenceCollectRequest",
                "ComplianceEvidenceBundleView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/compliance/evidence/bundles",
            op_list_protected(
                "Governance",
                "listComplianceEvidenceBundles",
                "List rendered evidence bundles.",
                "Returns paginated evidence-bundle records. Requires bearer token \
             (`compliance:read`).",
                "ComplianceEvidenceBundleView",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/compliance/evidence/bundles/{id}/download",
            op_get_one_with_params(
                "Governance",
                "downloadComplianceEvidenceBundle",
                "Download an evidence bundle.",
                "Streams the bundle archive (zip). Requires bearer token \
             (`compliance:read`). Response is `application/zip`.",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit",
            op_list_protected(
                "Governance",
                "listAudit",
                "List audit events (alias).",
                "Alias of `/v1/audit/search`. Returns the recent audit log. Requires bearer \
             token (`audit:read`).",
                "AuditEvent",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit/search",
            op_list_protected(
                "Governance",
                "searchAudit",
                "Search audit events.",
                "Filtered audit-log search (`actor`, `action`, `subject`, `since`, `until`). \
             Requires bearer token (`audit:read`).",
                "AuditEvent",
                &[
                    query_string("actor"),
                    query_string("action"),
                    query_string("subject"),
                    query_string("since"),
                    query_string("until"),
                ],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit/replay",
            op_list_protected(
                "Governance",
                "replayAudit",
                "Replay an audit window.",
                "Returns ordered audit events for replay (e.g. for forensics). Requires bearer \
             token (`audit:read`).",
                "AuditEvent",
                &[query_string("since"), query_string("until")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit/diff",
            op_get_one_protected(
                "Governance",
                "diffAudit",
                "Diff two audit snapshots.",
                "Returns a structured diff between two audit points (e.g. policy diff). \
             Requires bearer token (`audit:read`).",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit/export",
            op_list_protected(
                "Governance",
                "exportAuditNdjson",
                "Export audit events as NDJSON.",
                "Streams audit events as newline-delimited JSON. Requires bearer token \
             (`audit:read`). Response is `application/x-ndjson`.",
                "AuditEvent",
                &[query_string("since"), query_string("until")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/audit/anchors",
            op_list_protected(
                "Governance",
                "listAuditAnchors",
                "List tamper-evidence anchors.",
                "Returns Merkle-tree audit anchors. Requires bearer token (`audit:read`).",
                "AuditAnchorView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/audit/anchors/verify/{run_id}",
            op_action_protected(
                "Governance",
                "verifyAuditAnchor",
                "Verify an audit anchor.",
                "Recomputes the Merkle root for `run_id` and verifies it matches the stored \
             anchor. Returns mismatch details if tampered. Requires bearer token \
             (`audit:read`).",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/grc/configs",
            op_list_protected(
                "Governance",
                "listGrcConfigs",
                "List GRC integration configurations.",
                "Returns the configured downstream GRC integrations (ServiceNow, Jira, Archer, \
             …). Requires bearer token (`grc:read`).",
                "GrcConfig",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/grc/configs",
            op_post_protected(
                "Governance",
                "upsertGrcConfig",
                "Create or update a GRC integration configuration.",
                "Upserts the GRC connector record. Requires bearer token (`grc:write`).",
                "GrcConfig",
                "GrcConfig",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/grc/configs/{kind}/test",
            op_mutate_protected_with_params(
                "Governance",
                "testGrcConfig",
                "Test a GRC integration connection.",
                "Performs a no-op probe against the configured GRC endpoint. Requires bearer \
             token (`grc:write`).",
                "GrcConfigTestRequest",
                "GenericData",
                &[path_string("kind")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/grc/push",
            op_post_protected(
                "Governance",
                "pushToGrc",
                "Push records to a GRC system.",
                "Sends a batch of records to the configured GRC integration. Side effect: \
             creates tickets/findings in the downstream tool. Requires bearer token \
             (`grc:write`).",
                "GrcPushRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/ir/playbooks",
            op_list_protected(
                "Governance",
                "listIrPlaybooks",
                "List IR playbooks.",
                "Returns the catalog of incident-response playbooks. Requires bearer token \
             (`ir:read`).",
                "IrPlaybookView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/ir/incidents",
            op_post_protected(
                "Governance",
                "openIrIncident",
                "Open an IR incident from a playbook.",
                "Instantiates a playbook into an in-progress incident. Side effect: notifies \
             on-call. Requires bearer token (`ir:write`).",
                "IrIncidentOpen",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/ir/incidents/{id}",
            op_get_one_with_params(
                "Governance",
                "getIrIncident",
                "Get an IR incident.",
                "Returns the full incident record (steps, evidence, comments). Requires bearer \
             token (`ir:read`).",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "PATCH",
            "/v1/ir/incidents/{id}/steps/{step}",
            op_mutate_protected_with_params(
                "Governance",
                "updateIrIncidentStep",
                "Update an IR incident step.",
                "Patches a step's status / notes. Audit-logged. Requires bearer token \
             (`ir:write`).",
                "IrIncidentStepUpdate",
                "GenericData",
                &[path_string("id"), path_string("step")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/dlp/config",
            op_get_one_protected(
                "Governance",
                "getDlpConfig",
                "Get the DLP configuration.",
                "Returns the active DLP rule set. Requires bearer token (`dlp:read`).",
                "DlpConfig",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/dlp/config",
            op_post_protected(
                "Governance",
                "putDlpConfig",
                "Replace the DLP configuration.",
                "Atomically replaces the active rule set. Audit-logged. Requires bearer token \
             (`dlp:write`).",
                "DlpConfig",
                "DlpConfig",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/dlp/scan",
            op_post_protected(
                "Governance",
                "scanDlp",
                "Scan content against DLP rules.",
                "Returns the rule hits (PII, secrets, …). Stateless. Requires bearer token \
             (`dlp:read`).",
                "DlpScanRequest",
                "GenericData",
            ),
        ),
        // HIGH-004 — per-tenant DLP fusion threshold (admin).
        PathEntry::new(
            "GET",
            "/v1/admin/dlp/thresholds",
            op_get_one_protected(
                "Governance",
                "getDlpThreshold",
                "Get the DLP minimum-confidence threshold.",
                "Returns the per-tenant fused-confidence threshold applied to every DLP finding \
             (HIGH-004). Requires bearer token (`admin:dlp`).",
                "DlpConfig",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/admin/dlp/thresholds",
            op_post_protected(
                "Governance",
                "putDlpThreshold",
                "Replace the DLP minimum-confidence threshold.",
                "Sets the per-tenant fused-confidence threshold (HIGH-004). Audit-logged. \
             Requires bearer token (`admin:dlp`).",
                "DlpConfig",
                "DlpConfig",
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: AI Audit — AI-SEC-001 inventory, AI-BOM, controls, run.
// ---------------------------------------------------------------------------

fn ai_audit_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/v1/ai-audit/assets",
            op_list_protected(
                "AI Audit",
                "listAiAssets",
                "List inventoried AI assets.",
                "Returns the AI asset inventory (LLM endpoints, model registries, vector \
                 stores, model files, agent frameworks, MCP servers) for the caller's tenant. \
                 Requires bearer token (`ai_audit:read`).",
                "AiAssetListResponse",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/ai-audit/aibom",
            op_get_one_protected(
                "AI Audit",
                "getAiBom",
                "Build the tenant AI-BOM.",
                "Returns a CycloneDX-ML-style AI Bill of Materials for the caller's tenant. \
                 Requires bearer token (`ai_audit:read`).",
                "AiBomView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/ai-audit/controls",
            op_list_protected(
                "AI Audit",
                "listAiControls",
                "List AI governance controls.",
                "Returns the built-in AI governance controls (NIST AI RMF, ISO/IEC 42001, \
                 EU AI Act). Requires bearer token (`ai_audit:read`).",
                "AiControlListResponse",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/ai-audit/run",
            op_post_protected(
                "AI Audit",
                "runAiAudit",
                "Run a full AI security audit.",
                "Runs inventory + AI-BOM + governance evidence (and, when an in-scope probe \
                 target is configured, the prompt-injection probe corpus) for the caller's \
                 tenant, returning an AiAuditReportView. The run is recorded to the \
                 copilot-decision audit sink. Requires bearer token (`ai_audit:run`).",
                "GenericRequest",
                "AiAuditReportView",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/ai-audit/run-external",
            op_post_protected(
                "AI Audit",
                "runExternalAiAudit",
                "Red-team a config-registered external LLM target.",
                "Runs the prompt-injection probe corpus against a config-registered external \
                 LLM endpoint (`ai_copilot.external_targets`). Body: {engagement_id, target_id}. \
                 The target's host must be in scope of the named Active, in-window, approved \
                 engagement or the call is rejected 403. Requires bearer token (`ai_audit:run`).",
                "GenericRequest",
                "AiAuditReportView",
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Module: Developer — OpenAPI, plugins, chaos, risk tuning, bug bounty,
// notifications, autonomy/threat-network, collab tokens, SOAR, health.
// ---------------------------------------------------------------------------

fn developer_routes() -> Vec<PathEntry> {
    vec![
        PathEntry::new(
            "GET",
            "/openapi.json",
            op_public_get(
                "Developer",
                "getOpenApi",
                "OpenAPI 3.1 schema for this API.",
                "Returns the full machine-readable OpenAPI document. **Public** endpoint — \
             served on the public subrouter so REST tooling can fetch it without first \
             authenticating.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/healthz",
            op_public_get(
                "Developer",
                "healthz",
                "Liveness probe.",
                "Returns `200 OK` if the process is alive. **Public** endpoint.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/readyz",
            op_public_get(
                "Developer",
                "readyz",
                "Readiness probe.",
                "Returns `200` when downstream dependencies (DB, queue) are healthy; `503` \
             otherwise. **Public** endpoint.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/metrics",
            op_public_get(
                "Developer",
                "metrics",
                "Prometheus metrics.",
                "Returns the Prometheus exposition format. **Public** endpoint — intended for \
             scraping by Prometheus inside the cluster.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/plugins",
            op_list_protected(
                "Developer",
                "listPlugins",
                "List installed plugins.",
                "Returns metadata for installed plugins. Requires bearer token \
             (`plugin:read`).",
                "PluginView",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/plugins/install",
            op_post_protected(
                "Developer",
                "installPlugin",
                "Install a plugin from a manifest URL.",
                "Downloads, verifies (sha256), and registers a plugin. Side effect: writes \
             plugin record and may trigger init dispatch. Requires bearer token \
             (`plugin:write`).",
                "PluginInstallRequest",
                "PluginView",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/plugins/{id}",
            op_delete_with_params(
                "Developer",
                "uninstallPlugin",
                "Uninstall a plugin.",
                "Removes the plugin and stops all of its in-flight dispatches. Requires bearer \
             token (`plugin:write`).",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/plugins/{id}/dispatches",
            op_list_with_params(
                "Developer",
                "listPluginDispatches",
                "List recent dispatches for a plugin.",
                "Returns dispatch history (event, status, latency). Requires bearer token \
             (`plugin:read`).",
                "GenericData",
                &[path_string("id"), query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/chaos/config",
            op_get_one_protected(
                "Developer",
                "getChaosConfig",
                "Get the chaos-engineering configuration.",
                "Returns the chaos config (failure-rate, blast-radius). Requires bearer token \
             (`chaos:read`).",
                "ChaosConfig",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/chaos/config",
            op_post_protected(
                "Developer",
                "putChaosConfig",
                "Replace the chaos-engineering configuration.",
                "Updates the chaos parameters. Audit-logged. Requires bearer token \
             (`chaos:write`).",
                "ChaosConfig",
                "ChaosConfig",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/risk/config",
            op_get_one_protected(
                "Developer",
                "getRiskConfig",
                "Get the risk-tuning configuration.",
                "Returns tenant-level risk-tuning weights. Requires bearer token \
             (`risk:read`).",
                "RiskTuningConfig",
            ),
        ),
        PathEntry::new(
            "PUT",
            "/v1/risk/config",
            op_post_protected(
                "Developer",
                "putRiskConfig",
                "Update the risk-tuning configuration.",
                "Updates risk-scoring weights. Audit-logged. Requires bearer token \
             (`risk:write`).",
                "RiskTuningConfig",
                "RiskTuningConfig",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/risk/config/effective",
            op_get_one_protected(
                "Developer",
                "getEffectiveRiskConfig",
                "Get the effective (merged) risk configuration.",
                "Returns the resolved configuration after merging tenant overrides with \
             defaults. Requires bearer token (`risk:read`).",
                "RiskTuningConfig",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/notifications/devices",
            op_list_protected(
                "Developer",
                "listPushDevices",
                "List registered mobile push devices.",
                "Returns the caller's push-registered devices. Requires bearer token.",
                "GenericData",
                &[],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/integrations/bugbounty/configs",
            op_list_protected(
                "Developer",
                "listBugBountyConfigs",
                "List bug-bounty platform integrations.",
                "Returns configured HackerOne/Bugcrowd/Intigriti integrations. Requires bearer \
             token (`integrations:read`).",
                "BugBountyConfig",
                &[],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/integrations/bugbounty/configs",
            op_post_protected(
                "Developer",
                "upsertBugBountyConfig",
                "Create or update a bug-bounty integration.",
                "Upserts the integration record (credentials stored via secrets ref). Requires \
             bearer token (`integrations:write`).",
                "BugBountyConfig",
                "BugBountyConfig",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/integrations/bugbounty/push",
            op_post_protected(
                "Developer",
                "pushBugBountyReport",
                "Push a finding to a bug-bounty platform.",
                "Submits a finding as a bug-bounty report. Side effect: creates a report on the \
             remote platform. Requires bearer token (`integrations:write`).",
                "BugBountyPushRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/integrations/bugbounty/inbound/{platform}",
            op_public_post_with_params(
                "Developer",
                "bugBountyInbound",
                "Receive an inbound bug-bounty webhook.",
                "Vendor webhook endpoint. **Authenticated by HMAC signature** in the request \
             header, not a bearer token. `platform` path param identifies the vendor.",
                "BugBountyInboundPayload",
                "GenericData",
                &[path_string("platform")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/collab/tokens",
            op_post_protected(
                "Developer",
                "allocateCollabToken",
                "Allocate a collaboration callback token.",
                "Issues a short-lived token used for collaboration callbacks (e.g. webhook). \
             Requires bearer token (`collab:write`).",
                "CollabTokenRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/collab/tokens/{token}/callbacks",
            op_list_with_params(
                "Developer",
                "listCollabCallbacks",
                "List callbacks received for a token.",
                "Returns the callbacks captured against a collaboration token. Requires bearer \
             token.",
                "GenericData",
                &[path_string("token")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/soar/workflows",
            op_list_protected(
                "Developer",
                "listSoarWorkflows",
                "List SOAR workflows.",
                "Returns paginated SOAR workflow definitions. Requires bearer token \
             (`soar:read`).",
                "WorkflowSummaryView",
                &[query_int("limit"), query_int("offset")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/soar/workflows",
            op_post_protected(
                "Developer",
                "createSoarWorkflow",
                "Create a SOAR workflow.",
                "Persists a new SOAR workflow definition. Requires bearer token \
             (`soar:write`).",
                "SoarWorkflowCreate",
                "WorkflowSummaryView",
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/soar/workflows/{id}",
            op_get_one_with_params(
                "Developer",
                "getSoarWorkflow",
                "Get a SOAR workflow.",
                "Returns the full workflow definition. Requires bearer token (`soar:read`).",
                "WorkflowSummaryView",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/soar/workflows/{id}/run",
            op_mutate_protected_with_params(
                "Developer",
                "runSoarWorkflow",
                "Start a SOAR workflow run.",
                "Enqueues a run with the supplied execution context. Requires bearer token \
             (`soar:run`).",
                "SoarRunRequest",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "GET",
            "/v1/soar/runs/{id}",
            op_get_one_with_params(
                "Developer",
                "getSoarRun",
                "Get a SOAR workflow run.",
                "Returns the run state and step outcomes. Requires bearer token (`soar:read`).",
                "GenericData",
                &[path_string("id")],
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/autonomy/pr",
            op_post_protected(
                "Developer",
                "autonomyProposePr",
                "Ask autonomy to propose a remediation PR.",
                "Generates and (optionally) opens a remediation pull request via a configured \
             VCS integration. Requires bearer token (`autonomy:write`).",
                "AutonomyPrRequest",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/autonomy/threat-network",
            op_post_protected(
                "Developer",
                "autonomySubmitThreat",
                "Submit a threat-network observation.",
                "Pushes anonymised IOCs / TTPs into the cross-tenant threat-network. Requires \
             bearer token (`autonomy:write`).",
                "ThreatNetworkSubmission",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "POST",
            "/v1/autonomy/validation/schedules",
            op_post_protected(
                "Developer",
                "autonomyScheduleValidation",
                "Schedule a recurring autonomy validation.",
                "Registers a cron-style schedule for an autonomy engine. Requires bearer token \
             (`autonomy:write`).",
                "ValidationSchedule",
                "GenericData",
            ),
        ),
        PathEntry::new(
            "DELETE",
            "/v1/autonomy/validation/schedules/{engine_id}",
            op_delete_with_params(
                "Developer",
                "autonomyCancelValidation",
                "Cancel a scheduled autonomy validation.",
                "Removes a recurring autonomy validation by engine id. Requires bearer token \
             (`autonomy:write`).",
                &[path_string("engine_id")],
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Operation-builder helpers
// ---------------------------------------------------------------------------

fn op_list_protected(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    item_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "responses": ok_array(format!("List of {item_schema}.").as_str(), item_schema)
    });
    if !params.is_empty() {
        op["parameters"] = Value::Array(params.to_vec());
    }
    op
}

fn op_list_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    item_schema: &str,
    params: &[Value],
) -> Value {
    op_list_protected(tag, op_id, summary, description, item_schema, params)
}

fn op_post_protected(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    request_schema: &str,
    response_schema: &str,
) -> Value {
    json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "requestBody": request_body(request_schema),
        "responses": ok_response(format!("{response_schema} returned.").as_str(), response_schema)
    })
}

fn op_post_protected_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    request_schema: &str,
    response_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = op_post_protected(
        tag,
        op_id,
        summary,
        description,
        request_schema,
        response_schema,
    );
    op["parameters"] = Value::Array(params.to_vec());
    op
}

fn op_mutate_protected_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    request_schema: &str,
    response_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = op_post_protected(
        tag,
        op_id,
        summary,
        description,
        request_schema,
        response_schema,
    );
    op["parameters"] = Value::Array(params.to_vec());
    op["responses"]["404"] = json!({
        "description": "Resource not found.",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } }
    });
    op
}

fn op_get_one_protected(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    response_schema: &str,
) -> Value {
    json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "responses": ok_response(format!("{response_schema} returned.").as_str(), response_schema)
    })
}

fn op_get_one_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    response_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = op_get_one_protected(tag, op_id, summary, description, response_schema);
    op["parameters"] = Value::Array(params.to_vec());
    op["responses"]["404"] = json!({
        "description": "Resource not found.",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } }
    });
    op
}

fn op_action_protected(tag: &str, op_id: &str, summary: &str, description: &str) -> Value {
    json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "parameters": [path_string("id")],
        "responses": ok_empty("Action accepted.")
    })
}

fn op_delete_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    params: &[Value],
) -> Value {
    json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "parameters": params,
        "responses": ok_empty("Deleted.")
    })
}

fn op_public_get(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    response_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "security": [],
        "responses": ok_response(format!("{response_schema} returned.").as_str(), response_schema)
    });
    if !params.is_empty() {
        op["parameters"] = Value::Array(params.to_vec());
    }
    op
}

fn op_public_post(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    request_schema: &str,
    response_schema: &str,
) -> Value {
    json!({
        "tags": [tag],
        "operationId": op_id,
        "summary": summary,
        "description": description,
        "security": [],
        "requestBody": request_body(request_schema),
        "responses": ok_response(format!("{response_schema} returned.").as_str(), response_schema)
    })
}

fn op_public_post_with_params(
    tag: &str,
    op_id: &str,
    summary: &str,
    description: &str,
    request_schema: &str,
    response_schema: &str,
    params: &[Value],
) -> Value {
    let mut op = op_public_post(
        tag,
        op_id,
        summary,
        description,
        request_schema,
        response_schema,
    );
    op["parameters"] = Value::Array(params.to_vec());
    op
}

fn request_body(schema_name: &str) -> Value {
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
            }
        }
    })
}

/// Helper: build a standard `responses` block for an envelope wrapping a single object.
fn ok_response(description: &str, schema_name: &str) -> Value {
    json!({
        "200": {
            "description": description,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["data", "meta"],
                        "properties": {
                            "data": { "$ref": format!("#/components/schemas/{schema_name}") },
                            "meta": { "$ref": "#/components/schemas/EnvelopeMeta" }
                        }
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "403": {
            "description": "Forbidden.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "422": {
            "description": "Validation failed.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "default": {
            "description": "Error envelope.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        }
    })
}

/// Helper: responses block for an array payload.
fn ok_array(description: &str, schema_name: &str) -> Value {
    json!({
        "200": {
            "description": description,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["data", "meta"],
                        "properties": {
                            "data": {
                                "type": "object",
                                "properties": {
                                    "items": {
                                        "type": "array",
                                        "items": { "$ref": format!("#/components/schemas/{schema_name}") }
                                    },
                                    "total": { "type": "integer", "format": "int64" }
                                }
                            },
                            "meta": { "$ref": "#/components/schemas/EnvelopeMeta" }
                        }
                    }
                }
            }
        },
        "401": {
            "description": "Unauthorized.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "403": {
            "description": "Forbidden.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "default": {
            "description": "Error envelope.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        }
    })
}

/// Helper: responses block for an empty-body 200 / 204 (e.g. logout, delete).
fn ok_empty(description: &str) -> Value {
    json!({
        "200": { "description": description },
        "204": { "description": "No content." },
        "401": {
            "description": "Unauthorized.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "403": {
            "description": "Forbidden.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        },
        "default": {
            "description": "Error envelope.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/ApiError" }
                }
            }
        }
    })
}

/// Helper: a path parameter of type `string`.
fn path_string(name: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "schema": { "type": "string" }
    })
}

/// Helper: a query parameter of type `string` (optional).
fn query_string(name: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "schema": { "type": "string" }
    })
}

/// Helper: a query parameter of type `integer` (optional).
fn query_int(name: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "schema": { "type": "integer", "format": "int32" }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn document_has_openapi_3_1() {
        let doc = build_document();
        assert_eq!(doc["openapi"], "3.1.0");
    }

    #[test]
    fn document_contains_info_block() {
        let doc = build_document();
        assert_eq!(doc["info"]["title"], "SentinelX API");
        assert_eq!(doc["info"]["version"], "1.1.0");
    }

    #[test]
    fn document_serialises_to_valid_json() {
        let doc = build_document();
        let s = serde_json::to_string(&doc).unwrap();
        let parsed: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["openapi"], "3.1.0");
    }

    #[test]
    fn document_lists_at_least_100_paths() {
        let doc = build_document();
        let paths = doc["paths"].as_object().expect("paths must be an object");
        let mut ops = 0_usize;
        let method_keys = ["get", "post", "put", "patch", "delete", "options", "head"];
        for (_, item) in paths {
            for m in &method_keys {
                if item.get(*m).is_some() {
                    ops += 1;
                }
            }
        }
        #[allow(clippy::print_stderr, clippy::disallowed_macros)]
        // test introspection output captured by `--nocapture`
        {
            eprintln!(
                "openapi: paths={}, total method-path operations={}",
                paths.len(),
                ops
            );
        }
        assert!(
            paths.len() >= 100,
            "expected at least 100 paths, found {}",
            paths.len()
        );
    }

    #[test]
    fn each_path_has_at_least_one_method() {
        let doc = build_document();
        let paths = doc["paths"].as_object().expect("paths");
        for (name, path_item) in paths {
            let item = path_item
                .as_object()
                .unwrap_or_else(|| panic!("path {name} is not an object"));
            let method_keys = ["get", "post", "put", "patch", "delete", "options", "head"];
            let has_any = method_keys.iter().any(|m| item.contains_key(*m));
            assert!(has_any, "path {name} has no HTTP methods defined");
        }
    }

    #[test]
    fn document_covers_the_required_endpoints() {
        let doc = build_document();
        let paths = doc["paths"].as_object().unwrap();
        for required in [
            "/v1/auth/login",
            "/v1/engagements",
            "/v1/findings",
            "/v1/assets",
            "/v1/risk/calculate",
            "/v1/bas/run",
            "/v1/soc/alerts",
            "/v1/copilot/chat",
            "/v1/admin/users",
            "/v1/admin/roles",
            "/v1/bas/chains",
            "/v1/compliance/evidence/bundles",
            "/v1/audit/anchors",
            "/v1/runtime/falco/alerts",
            "/v1/hunt/query",
            "/v1/ueba/anomalies",
            "/v1/device-trust/policy",
            "/v1/dlp/scan",
            "/v1/ir/playbooks",
            "/v1/grc/configs",
            "/v1/plugins",
            "/v1/chaos/config",
            "/v1/risk/config",
            "/v1/integrations/bugbounty/configs",
            "/v1/ai-audit/assets",
            "/v1/ai-audit/run",
            "/openapi.json",
            "/healthz",
            "/metrics",
            "/scim/v2/Users",
            "/v1/auth/saml/metadata",
            "/v1/cloud/inventory",
            "/v1/cloud/drift/scan",
            "/v1/discovery/dast/scan",
            "/v1/discovery/prowler/import",
            "/v1/cloud/blast-radius",
            "/v1/graph/attack-paths",
            "/v1/reports",
            "/v1/soar/workflows",
            "/v1/pentest/runs",
        ] {
            assert!(paths.contains_key(required), "missing path {required}");
        }
    }

    #[test]
    fn every_operation_has_an_operation_id() {
        let doc = build_document();
        let paths = doc["paths"].as_object().unwrap();
        let method_keys = ["get", "post", "put", "patch", "delete", "options", "head"];
        for (path, item) in paths {
            let obj = item
                .as_object()
                .unwrap_or_else(|| panic!("path {path} not object"));
            for method in &method_keys {
                if let Some(op) = obj.get(*method) {
                    assert!(
                        op.get("operationId").and_then(Value::as_str).is_some(),
                        "{path} {method} missing operationId"
                    );
                }
            }
        }
    }

    #[test]
    fn every_operation_has_a_tag() {
        let doc = build_document();
        let paths = doc["paths"].as_object().unwrap();
        let method_keys = ["get", "post", "put", "patch", "delete", "options", "head"];
        let allowed: std::collections::HashSet<&str> = [
            "Operations",
            "Engagement",
            "Discovery",
            "Offensive",
            "Pentest",
            "Detection",
            "Identity",
            "Governance",
            "AI Audit",
            "Developer",
        ]
        .into_iter()
        .collect();
        for (path, item) in paths {
            let obj = item.as_object().unwrap();
            for method in &method_keys {
                if let Some(op) = obj.get(*method) {
                    let tags = op["tags"]
                        .as_array()
                        .unwrap_or_else(|| panic!("{path} {method} missing tags array"));
                    let tag = tags[0].as_str().unwrap();
                    assert!(
                        allowed.contains(tag),
                        "{path} {method} has unknown tag {tag}"
                    );
                }
            }
        }
    }

    #[test]
    fn schemas_block_contains_referenced_types() {
        let doc = build_document();
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas object");
        for name in [
            "ApiError",
            "EnvelopeMeta",
            "GenericData",
            "TokenView",
            "Engagement",
            "Finding",
            "Asset",
            "RiskCalculateResponse",
            "BasRunResponse",
            "BasChainView",
            "SocAlert",
            "CopilotChatResponse",
            "CreateUserResponse",
            "Role",
            "TenantView",
            "ScimUser",
            "ScimGroup",
            "FeedStatusView",
            "ReportSummaryView",
            "WorkflowSummaryView",
            "ApiDastScanResultView",
            "ComplianceEvidenceBundleView",
            "BugBountyConfig",
            "DeviceTrustPolicy",
            "UebaAnomalyView",
            "AuditAnchorView",
            "IrPlaybookView",
            "PluginView",
            "ChaosConfig",
            "RiskTuningConfig",
            "RbaConfig",
            "DlpConfig",
            "GrcConfig",
        ] {
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
    }

    #[test]
    fn public_endpoints_have_empty_security() {
        let doc = build_document();
        let paths = doc["paths"].as_object().unwrap();
        for public in [
            "/healthz",
            "/readyz",
            "/metrics",
            "/openapi.json",
            "/v1/auth/login",
            "/v1/auth/refresh",
            "/v1/auth/saml/metadata",
            "/v1/auth/saml/acs",
            "/v1/runtime/falco/alerts",
        ] {
            let item = paths
                .get(public)
                .unwrap_or_else(|| panic!("{public} missing"));
            let methods: Vec<&str> = item
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            for m in methods {
                let op = &item[m];
                let security = op["security"].as_array().unwrap_or_else(|| {
                    panic!("{public} {m} missing security array (public must be [])")
                });
                assert!(
                    security.is_empty(),
                    "{public} {m} has non-empty security but should be public"
                );
            }
        }
    }

    #[tokio::test]
    async fn schema_handler_returns_json_payload() {
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let response = schema().await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), 4_194_304).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["openapi"], "3.1.0");
        assert!(v["paths"].is_object());
        assert!(v["paths"].as_object().unwrap().len() >= 100);
    }
}
