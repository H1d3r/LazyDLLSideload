use std::path::Path;

use lazy_dll_sideload::generate::{GenOpts, Mode, generate, hijack_present};
use lazy_dll_sideload::pe::{Export, parse_exports_from_bytes, parse_pe_exports};

fn opts(mode: Mode, absolute: bool) -> GenOpts {
    GenOpts {
        mode,
        dll_path: if absolute {
            Path::new(r"C:\Windows\System32\version.dll").to_path_buf()
        } else {
            Path::new("version.dll").to_path_buf()
        },
        dll_stem: "version".into(),
        hijack_export: "GetFileVersionInfoA".into(),
        original_dll_name: "version_orig.dll".into(),
        absolute,
    }
}

#[test]
fn generated_proxy_never_pins_git_dyncvoke() {
    let exports = vec![Export {
        name: Some("GetFileVersionInfoA".into()),
        ordinal: 1,
    }];
    let p = generate(&opts(Mode::Proxy, false), &exports);
    assert!(p.cargo_toml.contains("dyncvoke = \"0.1\""));
    assert!(!p.cargo_toml.contains("git"));
    assert!(p.lib_rs.contains("use dyncvoke::syscall"));
    assert!(p.lib_rs.contains("load_library_a"));
    assert!(p.lib_rs.contains("get_function_address"));
}

#[test]
fn generated_code_does_not_write_thread_handle_to_null() {
    let exports = vec![Export {
        name: Some("GetFileVersionInfoA".into()),
        ordinal: 1,
    }];
    let p = generate(&opts(Mode::Proxy, true), &exports);
    assert!(
        p.lib_rs
            .contains("let mut thread: *mut c_void = ptr::null_mut()")
    );
    assert!(p.lib_rs.contains("&mut thread as *mut *mut c_void"));
    assert!(!p.lib_rs.contains("*mut HANDLE = ptr::null_mut()"));
    assert!(p.lib_rs.contains("-1isize"));
    assert!(p.lib_rs.contains("0x1FFFFFu32"));
}

#[test]
fn live_version_dll_round_trip() {
    let path = Path::new(r"C:\Windows\System32\version.dll");
    if !path.exists() {
        return;
    }
    let exports = parse_pe_exports(path).expect("parse version.dll");
    assert!(hijack_present(&exports, "GetFileVersionInfoA"));
    let p = generate(&opts(Mode::Proxy, true), &exports);
    assert!(
        p.proxy_def
            .as_ref()
            .unwrap()
            .contains("GetFileVersionInfoA @")
    );
    assert!(p.forward_rs.contains("GetFileVersionInfoW") || exports.len() == 1);
    assert!(p.lib_rs.contains(r"C:\\Windows\\System32\\version.dll"));
}

#[test]
fn synthetic_pe_feeds_generator() {
    let pe =
        lazy_dll_sideload::pe::build_synthetic_pe32plus(&[("Alpha", 1), ("HijackMe", 2)], &[3]);
    let exports = parse_exports_from_bytes(&pe).unwrap();
    assert!(hijack_present(&exports, "HijackMe"));
    let mut g = opts(Mode::Sideload, false);
    g.hijack_export = "HijackMe".into();
    g.dll_stem = "toy".into();
    let p = generate(&g, &exports);
    assert!(p.lib_rs.contains("fn HijackMe"));
    assert!(p.forward_rs.contains("fn Alpha"));
    assert!(!p.forward_rs.contains("fn HijackMe"));
}
