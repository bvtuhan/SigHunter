use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
pub(crate) struct Cli {
    /// Process name to iterate over
    #[arg(short, long, value_name = "PROCESS.EXE")]
    pub(crate) process_name: String,

    /// Specific module inside the process, if not set all available modules are considered
    #[arg(short, long)]
    pub(crate) module_name: Option<String>,

    /// Signature to find
    #[arg(short, long, value_name = "SIGNATURE")]
    pub(crate) signature: String,

    /// Ignores system related modules (does not bring anything if module_name option is set)
    #[arg(short, long, default_value = "false")]
    pub(crate) ignore_os: bool,
}