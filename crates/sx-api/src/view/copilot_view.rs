//! AI Copilot chat DTOs.
//!
//! Wire-shape request and response types for the single Copilot route:
//!
//! - `POST /v1/copilot/chat` — send a single-turn prompt to the AI Copilot
//!   and receive an assistant reply.
//!
//! ## Validation
//!
//! - `prompt` is bounded `[1, 4000]` characters. The lower bound rejects
//!   trivially empty payloads; the upper bound is a defensive cap that
//!   sits well below the Anthropic Messages API per-message input limit
//!   and below the workspace-default `ai_copilot.max_tokens`.
//!
//! ## Security posture
//!
//! Neither the request nor the response is logged. The controller only
//! emits structured events carrying the prompt **length** and the reply
//! **length** — never the bodies themselves. See
//! [`crate::controller::copilot::chat`] for the on-wire posture.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/copilot/chat` request body.
///
/// A single-turn user prompt forwarded to the AI Copilot backend.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct CopilotChatRequest {
    /// Operator-supplied prompt. Bounded `[1, 4000]` characters to keep
    /// the upstream Messages API call within the workspace-default token
    /// budget and to reject trivially empty payloads.
    #[validate(length(min = 1, max = 4000))]
    pub prompt: String,
}

/// `POST /v1/copilot/chat` response body.
///
/// Mirrors the assistant text returned by the underlying LLM client plus
/// the model identifier so the caller can attribute the answer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CopilotChatResponse {
    /// Assistant reply text. Never logged by the API layer.
    pub reply: String,
    /// Model identifier that produced [`Self::reply`] (e.g.
    /// `claude-3-5-sonnet-latest`).
    pub model: String,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn baseline() -> CopilotChatRequest {
        CopilotChatRequest {
            prompt: "Summarise the last finding.".to_string(),
        }
    }

    #[test]
    fn accepts_well_formed_request() {
        assert!(baseline().validate().is_ok());
    }

    #[test]
    fn rejects_empty_prompt() {
        let req = CopilotChatRequest {
            prompt: String::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn rejects_prompt_above_four_thousand_chars() {
        let req = CopilotChatRequest {
            prompt: "a".repeat(4001),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn accepts_prompt_at_upper_bound() {
        let req = CopilotChatRequest {
            prompt: "a".repeat(4000),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn response_round_trips_through_json() {
        let resp = CopilotChatResponse {
            reply: "ok".into(),
            model: "claude-3-5-sonnet-latest".into(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        let back: CopilotChatResponse = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.reply, "ok");
        assert_eq!(back.model, "claude-3-5-sonnet-latest");
    }
}
