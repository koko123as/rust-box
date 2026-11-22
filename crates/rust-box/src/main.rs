//! The `rust-box` command, following sing-box's `cmd/sing-box`:
//! `run`, `check`, `version` and `rule-set`.

mod rule_set_cmd;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rust_box::{RustBox, VERSION};

#[derive(Parser)]
#[command(name = "rust-box", version = VERSION, about = "A Rust reimplementation modeled on sing-box")]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    /// Working directory
    #[arg(short = 'D', long = "directory", global = true)]
    directory: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run service
    Run(ConfigArgs),
    /// Check configuration
    Check(ConfigArgs),
    /// Print version
    Version,
    /// Manage rule-sets
    #[command(name = "rule-set")]
    RuleSet {
        #[command(subcommand)]
        command: rule_set_cmd::RuleSetCommand,
    },
}

/// `-c` is accepted before or after `run`/`check`; it is not a global
/// flag because `rule-set merge` has its own `-c` (as in sing-box, where
/// the subcommand's flag shadows the persistent one).
#[derive(clap::Args)]
struct ConfigArgs {
    /// Configuration file path
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
}

impl Cli {
    fn config_path(&self, args: &ConfigArgs) -> PathBuf {
        args.config.clone().or_else(|| self.config.clone()).unwrap_or_else(|| PathBuf::from("config.json"))
    }
}

fn load(path: &PathBuf) -> Result<rb_config::Options> {
    let content = std::fs::read_to_string(path).with_context(|| format!("read config at {}", path.display()))?;
    rb_config::parse(&content).with_context(|| format!("decode config at {}", path.display()))
}

fn init_log(options: &rb_config::LogOptions) -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    if options.disabled {
        return Ok(());
    }
    let level = match options.level.as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "" | "info" => "info",
        "warn" | "warning" => "warn",
        "error" | "fatal" | "panic" => "error",
        other => bail!("unknown log level: {other}"),
    };
    let builder =
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(level)).with_target(false);
    if !options.output.is_empty() {
        let file =
            std::fs::OpenOptions::new().create(true).append(true).open(&options.output).context("open log output")?;
        let builder = builder.with_ansi(false).with_writer(std::sync::Mutex::new(file));
        if options.timestamp {
            builder.finish().with(rb_clashapi::ObservableLayer).init()
        } else {
            builder.without_time().finish().with(rb_clashapi::ObservableLayer).init()
        }
    } else if options.timestamp {
        builder.finish().with(rb_clashapi::ObservableLayer).init()
    } else {
        builder.without_time().finish().with(rb_clashapi::ObservableLayer).init()
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(directory) = &cli.directory {
        std::env::set_current_dir(directory)
            .with_context(|| format!("set working directory {}", directory.display()))?;
    }
    match &cli.command {
        Command::RuleSet { .. } => {
            let Command::RuleSet { command } = cli.command else { unreachable!() };
            rule_set_cmd::run(command)
        }
        Command::Version => {
            println!("rust-box version {VERSION}");
            println!("Modeled on sing-box 1.14.4 configuration (subset)");
            Ok(())
        }
        Command::Check(args) => {
            let options = load(&cli.config_path(args))?;
            RustBox::new(&options)?;
            Ok(())
        }
        Command::Run(args) => {
            let options = load(&cli.config_path(args))?;
            init_log(&options.log)?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                let instance = RustBox::new(&options)?;
                instance.start().await?;
                wait_for_signal().await;
                tracing::info!("rust-box closing");
                instance.close().await;
                Ok(())
            })
        }
    }
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
