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
        /// AI provider (nvidia, claude, google)
        #[arg(short, long, default_value = "google")]
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
    /// Show audit logs
    Audit,
    /// Show version info
    Version,
}