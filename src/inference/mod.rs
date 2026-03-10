// Copyright (c) 2025 Mouda. All Rights Reserved. AGPL-3.0
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

// ═══ Common Error ═══
#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

// ═══════════════════════════════════════════
// NVIDIA NIM Client
// ═══════════════════════════════════════════
#[derive(Debug, Serialize)]
struct NimRequest {
    model: String,
    messages: Vec<NimMessage>,
    max_tokens: u32,
}

#[derive(Debug, Serialize)]
struct NimMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct NimResponse {
    choices: Option<Vec<NimChoice>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct NimChoice {
    message: NimMessageResponse,
}

#[derive(Debug, Deserialize)]
struct NimMessageResponse {
    content: String,
}

pub struct NimClient {
    api_key: String,
    client: Client,
}

impl NimClient {
    pub fn new(api_key: &str) -> Self {
        NimClient {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[NIM] API key not configured".to_string());
        }
        let request = NimRequest {
            model: "meta/llama-3.1-8b-instruct".to_string(),
            max_tokens: 1024,
            messages: vec![NimMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };
        let response = self.client
            .post("https://integrate.api.nvidia.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send().await?
            .json::<NimResponse>().await?;
        if let Some(err) = response.error {
            return Ok(format!("NIM Error: {}", err.message));
        }
        Ok(response.choices
            .and_then(|c| c.into_iter().next())
            .map(|c| c.message.content)
            .unwrap_or_else(|| "No response".to_string()))
    }
}

// ═══════════════════════════════════════════
// Anthropic Claude Client
// ═══════════════════════════════════════════
#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ClaudeMessage>,
}

#[derive(Debug, Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Option<Vec<ClaudeContent>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ClaudeContent {
    text: String,
}

pub struct ClaudeClient {
    api_key: String,
    client: Client,
}

impl ClaudeClient {
    pub fn new(api_key: &str) -> Self {
        ClaudeClient {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[Claude] API key not configured".to_string());
        }
        let request = ClaudeRequest {
            model: "claude-haiku-4-5-20251001".to_string(),
            max_tokens: 1024,
            messages: vec![ClaudeMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };
        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send().await?
            .json::<ClaudeResponse>().await?;
        if let Some(err) = response.error {
            return Ok(format!("Claude Error: {}", err.message));
        }
        Ok(response.content
            .and_then(|c| c.into_iter().next())
            .map(|c| c.text)
            .unwrap_or_else(|| "No response".to_string()))
    }
}

// ═══════════════════════════════════════════
// Google Gemini Client
// ═══════════════════════════════════════════
#[derive(Debug, Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
}

#[derive(Debug, Serialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Option<Vec<GeminiCandidate>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiContentResponse,
}

#[derive(Debug, Deserialize)]
struct GeminiContentResponse {
    parts: Vec<GeminiPartResponse>,
}

#[derive(Debug, Deserialize)]
struct GeminiPartResponse {
    text: String,
}

pub struct GeminiClient {
    api_key: String,
    client: Client,
    model: String,
}

impl GeminiClient {
    pub fn new(api_key: &str) -> Self {
        GeminiClient {
            api_key: api_key.to_string(),
            client: Client::new(),
            model: "gemini-2.5-flash-lite".to_string(),
        }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[Gemini] API key not configured".to_string());
        }
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );
        let request = GeminiRequest {
            contents: vec![GeminiContent {
                parts: vec![GeminiPart { text: prompt.to_string() }],
            }],
        };
        let response = self.client
            .post(&url)
            .json(&request)
            .send().await?
            .json::<GeminiResponse>().await?;
        if let Some(err) = response.error {
            return Ok(format!("Gemini Error: {}", err.message));
        }
        Ok(response.candidates
            .and_then(|c| c.into_iter().next())
            .and_then(|c| c.content.parts.into_iter().next())
            .map(|p| p.text)
            .unwrap_or_else(|| "No response".to_string()))
    }
}

// ═══════════════════════════════════════════
// Groq Client (LLaMA via Groq)
// ═══════════════════════════════════════════
#[derive(Debug, Serialize)]
struct GroqRequest {
    model: String,
    messages: Vec<GroqMessage>,
    max_tokens: u32,
}

#[derive(Debug, Serialize)]
struct GroqMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct GroqResponse {
    choices: Option<Vec<GroqChoice>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct GroqChoice {
    message: GroqMessageResponse,
}

#[derive(Debug, Deserialize)]
struct GroqMessageResponse {
    content: String,
}

pub struct GroqClient {
    api_key: String,
    client: Client,
}

impl GroqClient {
    pub fn new(api_key: &str) -> Self {
        GroqClient {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[Groq] API key not configured".to_string());
        }
        let request = GroqRequest {
            model: "llama-3.3-70b-versatile".to_string(),
            max_tokens: 1024,
            messages: vec![GroqMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };
        let response = self.client
            .post("https://api.groq.com/openai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send().await?
            .json::<GroqResponse>().await?;
        if let Some(err) = response.error {
            return Ok(format!("Groq Error: {}", err.message));
        }
        Ok(response.choices
            .and_then(|c| c.into_iter().next())
            .map(|c| c.message.content)
            .unwrap_or_else(|| "No response".to_string()))
    }
}

// ═══════════════════════════════════════════
// OpenAI Client
// ═══════════════════════════════════════════
#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    max_tokens: u32,
}

#[derive(Debug, Serialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Option<Vec<OpenAiChoice>>,
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessageResponse,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessageResponse {
    content: String,
}

pub struct OpenAiClient {
    api_key: String,
    client: Client,
}

impl OpenAiClient {
    pub fn new(api_key: &str) -> Self {
        OpenAiClient {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[OpenAI] API key not configured".to_string());
        }
        let request = OpenAiRequest {
            model: "gpt-4o-mini".to_string(),
            max_tokens: 1024,
            messages: vec![OpenAiMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };
        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send().await?
            .json::<OpenAiResponse>().await?;
        if let Some(err) = response.error {
            return Ok(format!("OpenAI Error: {}", err.message));
        }
        Ok(response.choices
            .and_then(|c| c.into_iter().next())
            .map(|c| c.message.content)
            .unwrap_or_else(|| "No response".to_string()))
    }
}
// ═══════════════════════════════════════════
// NVIDIA Cosmos Reason Client (Robotics)
// ═══════════════════════════════════════════
pub struct CosmosClient {
    api_key: String,
    client: Client,
}

impl CosmosClient {
    pub fn new(api_key: &str) -> Self {
        CosmosClient {
            api_key: api_key.to_string(),
            client: Client::new(),
        }
    }

    pub async fn reason(&self, scenario: &str) -> Result<String> {
        if self.api_key.is_empty() {
            return Ok("[Cosmos] API key not configured".to_string());
        }
        let request = serde_json::json!({
            "model": "nvidia/cosmos-reason1-7b",
            "messages": [{
                "role": "user",
                "content": format!("Analyze this robotics scenario for safety: {}", scenario)
            }],
            "max_tokens": 1024
        });
        let response = self.client
            .post("https://integrate.api.nvidia.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send().await?
            .json::<serde_json::Value>().await?;
        if let Some(err) = response.get("error") {
            return Ok(format!("Cosmos Error: {}", err));
        }
        Ok(response["choices"][0]["message"]["content"]
            .as_str().map(String::from)
            .unwrap_or_else(|| "No response".to_string()))
    }
}
// ═══════════════════════════════════════════
// Ollama Client (Local AI — No Internet)
// ═══════════════════════════════════════════
pub struct OllamaClient {
    base_url: String,
    client: Client,
}

impl OllamaClient {
    pub fn new(base_url: &str) -> Self {
        let url = if base_url.is_empty() { "http://localhost:11434" } else { base_url };
        OllamaClient { base_url: url.to_string(), client: Client::new() }
    }

    pub async fn chat(&self, prompt: &str, model: &str) -> Result<String> {
        let m = if model.is_empty() { "llama3.2" } else { model };
        let body = serde_json::json!({"model": m, "prompt": prompt, "stream": false});
        let resp = self.client.post(&format!("{}/api/generate", self.base_url))
            .json(&body).send().await?
            .json::<serde_json::Value>().await?;
        Ok(resp["response"].as_str().map(String::from)
            .unwrap_or_else(|| "[Ollama] No response or not running".to_string()))
    }
}

// ═══════════════════════════════════════════
// Mistral Client
// ═══════════════════════════════════════════
pub struct MistralClient {
    api_key: String,
    client: Client,
}

impl MistralClient {
    pub fn new(api_key: &str) -> Self {
        MistralClient { api_key: api_key.to_string(), client: Client::new() }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() { return Ok("[Mistral] API key not configured".to_string()); }
        let body = serde_json::json!({
            "model": "mistral-small-latest",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024
        });
        let resp = self.client.post("https://api.mistral.ai/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body).send().await?
            .json::<serde_json::Value>().await?;
        if let Some(err) = resp.get("error") { return Ok(format!("Mistral Error: {}", err)); }
        Ok(resp["choices"][0]["message"]["content"].as_str().map(String::from)
            .unwrap_or_else(|| "No response".to_string()))
    }
}

// ═══════════════════════════════════════════
// DeepSeek Client
// ═══════════════════════════════════════════
pub struct DeepSeekClient {
    api_key: String,
    client: Client,
}

impl DeepSeekClient {
    pub fn new(api_key: &str) -> Self {
        DeepSeekClient { api_key: api_key.to_string(), client: Client::new() }
    }

    pub async fn chat(&self, prompt: &str) -> Result<String> {
        if self.api_key.is_empty() { return Ok("[DeepSeek] API key not configured".to_string()); }
        let body = serde_json::json!({
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024
        });
        let resp = self.client.post("https://api.deepseek.com/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body).send().await?
            .json::<serde_json::Value>().await?;
        if let Some(err) = resp.get("error") { return Ok(format!("DeepSeek Error: {}", err)); }
        Ok(resp["choices"][0]["message"]["content"].as_str().map(String::from)
            .unwrap_or_else(|| "No response".to_string()))
    }
}