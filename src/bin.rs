pub(crate) mod cli;

use anyhow::Ok;
use clap::Parser;
use memflow::mem::MemoryView;
use sighunter_lib::signature::Signature;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    let mut os = sighunter_lib::init_os()?;

    let mut process = sighunter_lib::get_process(&mut os, &cli.process_name)?;

    let modules = sighunter_lib::get_modules(&mut process, cli.module_name, cli.ignore_os)?;

    println!("[*] Iterating over {} different modules", modules.len());

    let signature = Signature::new(&cli.signature)?;

    modules.iter().try_for_each(|module| {
        let module_name = module.name.to_string();
        let mut buffer = vec![0u8; module.size as usize];
        process.read_raw_into(module.base, &mut buffer)?;
        if let Some(offset) = signature.find(&buffer) {
            println!("[+] Found signature at offset {module_name} + 0x{offset:X}");
        } else {
            println!("[-] No matching signature in module {module_name}");
        }
        Ok(())
    })
}
