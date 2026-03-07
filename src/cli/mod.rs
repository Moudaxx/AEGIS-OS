use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "aegis",
    about = "AEGIS OS - Secure Agent Execution Platform",
    version = "4.0"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a new agent
    Run {
        /// Agent name
        #[arg(short, long)]
        name: String,
        /// AI provider (nvidia, claude, google, groq, openai)
        #[arg(short, long, default_value = "groq")]
        provider: String,
    },
    /// Stop a running agent
    Stop {
        /// Agent ID
        #[arg(short, long)]
        id: String,
    },
    /// List all agents
    List,
    /// Show agent status
    Status {
        /// Agent ID
        #[arg(short, long)]
        id: String,
    },
    /// Show risk score
    RiskScore {
        /// Agent ID
        #[arg(short, long)]
        id: String,
    },
    /// Start red team test
    RedTeam {
        /// Target agent (optional)
        #[arg(short, long)]
        target: Option<String>,
    },
    /// Start HTTP server
    Serve {
        /// Port number (default: 8401)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Start HTTPS server with TLS
    ServeTls {
        /// Port number (default: 8443)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Show audit logs
    Audit,
    /// Show version info
    Version,
}