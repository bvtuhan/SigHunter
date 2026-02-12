use std::collections::HashSet;

use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub struct Signature {
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

pub const IGNORED_MODULES: once_cell::unsync::Lazy<HashSet<&'static str>> =
    once_cell::unsync::Lazy::new(|| {
        HashSet::from([
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "win32u.dll",
            "gdi32.dll",
            "gdi32full.dll",
            "msvcp_win.dll",
            "ucrtbase.dll",
            "imm32.dll",
            "advapi32.dll",
            "msvcrt.dll",
            "sechost.dll",
            "rpcrt4.dll",
            "ole32.dll",
            "combase.dll",
            "oleaut32.dll",
            "psapi.dll",
            "cfgmgr32.dll",
            "winmm.dll",
            "wintrust.dll",
            "crypt32.dll",
            "msasn1.dll",
            "ws2_32.dll",
            "bcrypt.dll",
            "bcryptprimitives.dll",
            "shell32.dll",
            "iphlpapi.dll",
            "wintypes.dll",
            "dbghelp.dll",
            "vfbasics.dll",
            "vrfcore.dll",
            "verifier.dll",
            "vconcomm.dll",
            "mswsock.dll",
            "imagehlp.dll",
            "setupapi.dll",
            "version.dll",
            "secur32.dll",
            "shlwapi.dll",
            "sspicli.dll",
            "shcore.dll",
            "cryptbase.dll",
            "wininet.dll",
            "kernel.appcore.dll",
            "uxtheme.dll",
            "dwmapi.dll",
            "dxgi.dll",
            "powrprof.dll",
            "umpdc.dll",
            "dxcore.dll",
            "devobj.dll",
            "imemanager.dll",
            "d3d9.dll",
            "d3d11.dll",
            "d3dcompiler_47.dll",
            "cryptnet.dll",
            "wldp.dll",
            "drvstore.dll",
            "cryptsp.dll",
            "rsaenh.dll",
            "windows.storage.dll",
            "profapi.dll",
            "ntmarta.dll",
            "msctf.dll",
            "mscms.dll",
            "textinputframework.dll",
            "clbcatq.dll",
            "dataexchange.dll",
            "twinapi.appcore.dll",
            "coremessaging.dll",
            "coreuicomponents.dll",
            "apphelp.dll",
            "dcomp.dll",
            "mmdevapi.dll",
            "audioses.dll",
            "windows.ui.dll",
            "wsock32.dll",
            "usp10.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "msvcp140.dll",
            "avrt.dll",
            "resourcepolicyclient.dll",
            "shfolder.dll",
            "propsys.dll",
            "networkexplorer.dll",
            "nsi.dll",
            "dhcpcsvc6.dll",
            "dhcpcsvc.dll",
            "dnsapi.dll",
            "rasadhlp.dll",
            "wbemprox.dll",
            "wbemcomn.dll",
            "napinsp.dll",
            "wbemsvc.dll",
            "winrnr.dll",
            "winhttp.dll",
            "nlansp_c.dll",
            "wshbth.dll",
            "fwpuclnt.dll",
            "fastprox.dll",
            "amsi.dll",
            "userenv.dll",
            "mpoav.dll",
            "gpapi.dll",
            "winnsi.dll",
            "textshaping.dll",
            "directxdatabasehelper.dll",
            "microsoft.internal.warppal.dll",
            "amd_ags_x64.dll",
            "nvapi64.dll",
            "nvspcap64.dll",
            "nvppex.dll",
            "nvldumdx.dll",
            "nvgpucomp64.dll",
            "nvmessagebus.dll",
            "nvmemmapstoragex.dll",
            "nvwgf2umx.dll",
            "aticfx64.dll",
            "atiuxp64.dll",
            "atidxx64.dll",
            "amdihk64.dll",
        ])
    });