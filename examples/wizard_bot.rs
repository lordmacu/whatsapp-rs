//! Multi-turn "form wizard" bot demonstrating per-JID persistent state.
//!
//! Walks each user through a 3-step onboarding (name → email → confirm)
//! and remembers where they were even across restarts. Each contact has
//! their own independent flow.
//!
//! ```bash
//! cargo run --release --example wizard_bot
//! ```
//!
//! State is stored as `agent-state/<jid>.json` in the current directory.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use whatsapp_rs::agent::{Acl, Response};
use whatsapp_rs::chat_state::StateStore;
use whatsapp_rs::Client;

#[derive(Default, Serialize, Deserialize, Debug)]
struct Wizard {
    step: Step,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq)]
enum Step {
    #[default]
    AskName,
    AskEmail,
    Confirm,
    Done,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whatsapp_rs=info")),
        )
        .init();

    let session = Client::new()?.connect().await?;
    tracing::info!("wizard bot ready as {}", session.our_jid);

    let state: StateStore<Wizard> = StateStore::open("agent-state")?;

    session.run_agent_with(Acl::from_env("WA_AGENT_ALLOW"), move |ctx| {
        let state = state.clone();
        async move {
            let jid = ctx.jid().to_string();
            let text = ctx.text.unwrap_or_default().trim().to_string();

            // `reset` at any point clears the wizard for this user.
            if text.eq_ignore_ascii_case("reset") {
                state.clear(&jid);
                return Response::text("🔄 reset — escribe cualquier cosa para empezar");
            }

            // Atomic RMW: read state, advance based on input, persist, return.
            let s = state.update(&jid, |s| match s.step {
                Step::AskName => {
                    s.name = Some(text.clone());
                    s.step = Step::AskEmail;
                }
                Step::AskEmail if text.contains('@') => {
                    s.email = Some(text.clone());
                    s.step = Step::Confirm;
                }
                Step::AskEmail => { /* stay; keep asking */ }
                Step::Confirm if text.eq_ignore_ascii_case("si") || text.eq_ignore_ascii_case("yes") => {
                    s.step = Step::Done;
                }
                Step::Confirm if text.eq_ignore_ascii_case("no") => {
                    s.step = Step::AskName;
                    s.name = None;
                    s.email = None;
                }
                Step::Confirm | Step::Done => {}
            });

            match s.step {
                Step::AskName   => Response::text("👋 ¿Cómo te llamas?"),
                Step::AskEmail  => Response::text(format!(
                    "Hola {}. ¿Cuál es tu email?",
                    s.name.as_deref().unwrap_or("")
                )),
                Step::Confirm   => Response::text(format!(
                    "Confirmar: {} / {} — ¿sí o no?",
                    s.name.as_deref().unwrap_or(""),
                    s.email.as_deref().unwrap_or(""),
                )),
                Step::Done      => Response::text("✅ listo — escribe `reset` para empezar de nuevo"),
            }
        }
    }).await?;

    Ok(())
}
