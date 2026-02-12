use memflow::{
    error::Result,
    mem::MemoryView,
    os::{ModuleInfo, Os, Process},
    plugins::os::{
        cglue_osinstance::OsInstanceArcBox, cglue_processinstance::ProcessInstanceArcBox,
    },
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub mod signature;

pub fn init_os() -> Result<OsInstanceArcBox<'static>> {
    let os = {
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
    Ok(os)
}

pub fn get_process<'a, T: AsRef<str>>(
    os: &'a mut OsInstanceArcBox<'_>,
    process_name: T,
) -> Result<ProcessInstanceArcBox<'a>> {
    os.process_by_name(process_name.as_ref())
}

pub fn get_modules<'a, T: AsRef<str>>(
    process: &mut ProcessInstanceArcBox<'a>,
    module_name: Option<T>,
    ignore_dos: bool,
) -> Result<Vec<ModuleInfo>> {
    let modules = process.module_list()?;

    if let Some(module_name) = module_name {
        let module = process.module_by_name(module_name.as_ref())?;
        Ok(vec![module])
    } else {
        if ignore_dos {
            Ok(modules
                .into_par_iter()
                .filter(|module| {
                    let module_name = module.name.to_string();
                    !signature::IGNORED_MODULES.contains(&module_name as &str)
                })
                .collect::<Vec<_>>())
        } else {
            Ok(modules)
        }
    }
}

pub fn read_module_bytes<'a, T: AsMut<[u8]>>(
    process: &'a mut ProcessInstanceArcBox<'a>,
    module: &'a ModuleInfo,
    mut out_buffer: T,
) -> Result<()> {
    let mut out_buffer = out_buffer.as_mut();
    process.read_raw_into(module.base, &mut out_buffer)?;
    Ok(())
}
