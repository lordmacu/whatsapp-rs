//! Voice-note bot: transcribes incoming audio, feeds the text to the agent
//! handler, and replies. Demonstrates the Transcriber extension point.
//!
//! This example hits an OpenAI-compatible `/audio/transcriptions` endpoint
//! but the Transcriber trait is just `(Vec<u8>, String) -> Option<String>`,
//! so you can swap in local Whisper, Google STT, Deepgram, a cached
//! fixture, etc. without touching the bot code.
//!
//! ```bash
//! export OPENAI_API_KEY=sk-…
//! export WA_AGENT_ALLOW=573…@s.whatsapp.net   # optional whitelist
//! cargo run --release --example voice_bot
//! ```
//!
//! Speak into the chat, the bot replies with the transcription it heard.

use anyhow::{bail, Result};
use whatsapp_rs::agent::{Acl, Response};
use whatsapp_rs::Client;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whatsapp_rs=info")),
        )
        .init();

    let api_key = match std::env::var("OPENAI_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => bail!("set OPENAI_API_KEY (or swap the transcriber for your own STT)"),
    };
    let api_url = std::env::var("OPENAI_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".into());

    let session = Client::new()?.connect().await?;
    tracing::info!("voice bot ready as {}", session.our_jid);

    let http = reqwest::Client::new();

    let transcribe = move |audio: Vec<u8>, mimetype: String| {
        let http = http.clone();
        let api_key = api_key.clone();
        let api_url = api_url.clone();
        async move {
            transcribe_via_openai(&http, &api_key, &api_url, audio, &mimetype)
                .await
                .ok()
        }
    };

    session.run_agent_with_transcribe(
        Acl::from_env("WA_AGENT_ALLOW"),
        transcribe,
        |ctx| async move {
            match ctx.text {
                Some(t) => Response::reply(format!("heard: {t}")),
                None => Response::Noop,
            }
        },
    ).await?;

    Ok(())
}

/// POST audio bytes to OpenAI's `/audio/transcriptions` (Whisper). Returns
/// the transcribed text or an error.
async fn transcribe_via_openai(
    http: &reqwest::Client,
    api_key: &str,
    api_url: &str,
    audio: Vec<u8>,
    mimetype: &str,
) -> Result<String> {
    // Guess a filename that matches the mime so the server routes to the
    // right decoder (WA voice notes are Opus/OGG).
    let filename = match mimetype {
        s if s.contains("ogg")  => "voice.ogg",
        s if s.contains("mp3")  => "voice.mp3",
        s if s.contains("mp4")  || s.contains("m4a") => "voice.m4a",
        s if s.contains("wav")  => "voice.wav",
        _                       => "voice.ogg",
    };
    let part = reqwest::multipart::Part::bytes(audio)
        .file_name(filename)
        .mime_str(mimetype)?;
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("model", "whisper-1");

    let resp = http.post(format!("{}/audio/transcriptions", api_url.trim_end_matches('/')))
        .bearer_auth(api_key)
        .multipart(form)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("whisper returned {}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    let body: serde_json::Value = serde_json::from_slice(&resp.bytes().await?)?;
    body.get("text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("whisper response missing .text"))
}
