use clap::Parser;
use ethereum_light_client_cli::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );
    Cli::parse().run().await
}
