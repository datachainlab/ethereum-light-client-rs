use clap::Parser;
pub use info::InfoCommand;
pub use init::InitCommand;
pub use update::UpdateCommand;

mod info;
mod init;
mod update;

#[derive(Parser, Debug)]
pub enum Command {
    #[clap(about = "Initialize light client")]
    Init(InitCommand),
    #[clap(about = "Update light client")]
    Update(UpdateCommand),
    #[clap(about = "Show info")]
    Info(InfoCommand),
}
