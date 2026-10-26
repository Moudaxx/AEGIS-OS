// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
//! AEGIS OS library: every security module, usable from the CLI binary,
//! integration tests (`tests/`) and other crates.

pub mod cli;
pub mod gateway;
pub mod orchestrator;
pub mod tool_router;
pub mod isolation;
pub mod state;
pub mod credentials;
pub mod risk;
pub mod audit;
pub mod guardrails;
pub mod sanitization;
pub mod skill_vetting;
pub mod inference;
pub mod mcp;
pub mod a2a;
pub mod redteam;
pub mod database;
pub mod ros2;
pub mod telemetry;
pub mod server;
pub mod kali;
pub mod rag_security;
pub mod privacy;
pub mod extraction_detect;
pub mod hallucination;
pub mod watermark;
pub mod discovery;
pub mod continuous_test;
pub mod learning;
pub mod reporter;
pub mod autonomous;
pub mod dashboard;
