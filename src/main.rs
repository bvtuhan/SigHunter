use crate::cli::IGNORED_MODULES;
use anyhow::Ok;
use clap::Parser;
use memflow::{
    mem::MemoryView,
    os::{Os, Process},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

mod cli;

struct Signature {
    raw_bytes: Vec<u8>,
    mask: Vec<bool>,
}

impl Signature {
    pub fn new(signature: &str) -> anyhow::Result<Self> {
        let mut raw_bytes = Vec::with_capacity(signature.len());
        let mut mask = Vec::with_capacity(signature.len());
        for sig in signature.split_whitespace() {
            if sig.eq("??") || sig.eq("?") {
                raw_bytes.push(0);
                mask.push(false);
                continue;
            }

            let byte = u8::from_str_radix(sig, 16)?;
            raw_bytes.push(byte);
            mask.push(true);
        }
        Ok(Self { raw_bytes, mask })
    }

    /// Returns the offset of the signature if any else None
    pub fn find(&self, module_bytes: &[u8]) -> Option<usize> {
        let read_size = self.raw_bytes.len();

        if read_size == 0 {
            return Some(0);
        }

        if read_size > module_bytes.len() {
            return None;
        }

        (0..module_bytes.len())
            .into_par_iter()
            .find_any(|&curr_offset| {
                if curr_offset + read_size <= module_bytes.len() {
                    let other_bytes_slice = &module_bytes[curr_offset..curr_offset + read_size];
                    return self.sig_match(other_bytes_slice);
                }
                false
            })
    }

    fn sig_match(&self, other: &[u8]) -> bool {
        for i in 0..self.raw_bytes.len() {
            if self.mask[i] && self.raw_bytes[i] != other[i] {
                return false;
            }
        }
        true
    }
}

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let mut os = {
        #[cfg(windows)]
        {
            use memflow::plugins::{LibArc, OsArgs};

            memflow_native::create_os(&OsArgs::default(), LibArc::default())?
        }
        #[cfg(not(windows))]
        {
            panic!("only windows is supported")
        }
    };

    let mut process = os.process_by_name(&cli.process_name)?;

    let modules = match cli.module_name {
        Some(module_name) => vec![process.module_by_name(&module_name)?],
        None => {
            let modules = process.module_list()?;

            if cli.ignore_os {
                modules
                    .into_par_iter()
                    .filter(|module| {
                        let module_name = module.name.to_string();
                        !IGNORED_MODULES.contains(&module_name as &str)
                    })
                    .collect::<Vec<_>>()
            } else {
                modules
            }
        }
    };

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
