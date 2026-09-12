use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ident::{cargo_package_name, is_rust_ident, rust_ident, rust_string_escape};
use crate::pe::Export;
use crate::{proxy, sideload};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Proxy,
    Sideload,
}

#[derive(Clone, Debug)]
pub struct GenOpts {
    pub mode: Mode,
    pub dll_path: PathBuf,
    pub dll_stem: String,
    pub hijack_export: String,
    pub original_dll_name: String,
    pub absolute: bool,
}

#[derive(Clone, Debug)]
pub struct GeneratedProject {
    pub package_name: String,
    pub cargo_toml: String,
    pub lib_rs: String,
    pub forward_rs: String,
    pub build_rs: Option<String>,
    pub proxy_def: Option<String>,
}

fn hijack_args(used: bool) -> String {
    (1..=20)
        .map(|i| {
            if used {
                format!("    a{i}: u64")
            } else {
                format!("    _a{i}: u64")
            }
        })
        .collect::<Vec<_>>()
        .join(",\n")
}

pub fn generate(opts: &GenOpts, exports: &[Export]) -> GeneratedProject {
    let package_name = cargo_package_name(&opts.dll_stem);
    match opts.mode {
        Mode::Proxy => generate_proxy(opts, exports, &package_name),
        Mode::Sideload => generate_sideload(opts, exports, &package_name),
    }
}

fn generate_proxy(opts: &GenOpts, exports: &[Export], package_name: &str) -> GeneratedProject {
    let original_dll_path = if opts.absolute {
        opts.dll_path.to_string_lossy().into_owned()
    } else {
        opts.original_dll_name.clone()
    };

    let hijack_fn = hijack_fn_src(&opts.hijack_export, "dispatch_call");
    let lib_rs = proxy::LIB_RS_TEMPLATE
        .replace(
            "{ORIGINAL_DLL_PATH}",
            &rust_string_escape(&original_dll_path),
        )
        .replace("{HIJACK_EXPORT}", &rust_string_escape(&opts.hijack_export))
        .replace("{HIJACK_FUNCTION}", &hijack_fn);

    let forward_rs = forward_stubs(exports, &opts.hijack_export);

    let forward_target = if opts.absolute {
        opts.dll_path
            .with_extension("")
            .to_string_lossy()
            .into_owned()
    } else {
        Path::new(&opts.original_dll_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(&opts.original_dll_name)
            .to_string()
    };

    let mut def = format!("LIBRARY {}\nEXPORTS\n", opts.dll_stem);
    let mut saw_hijack = false;
    for exp in exports {
        match &exp.name {
            Some(name) if name == &opts.hijack_export => {
                saw_hijack = true;
                def.push_str(&format!("{} @{}\n", name, exp.ordinal));
            }
            Some(name) => {
                def.push_str(&format!(
                    "{}={}.{} @{}\n",
                    name, forward_target, name, exp.ordinal
                ));
            }
            None => {
                def.push_str(&format!(
                    "ord_{}={}.#{} @{} NONAME\n",
                    exp.ordinal, forward_target, exp.ordinal, exp.ordinal
                ));
            }
        }
    }
    if !saw_hijack {
        def.push_str(&format!("{}\n", opts.hijack_export));
    }

    GeneratedProject {
        package_name: package_name.to_string(),
        cargo_toml: proxy::CARGO_TOML_TEMPLATE.replace("{PACKAGE_NAME}", package_name),
        lib_rs,
        forward_rs,
        build_rs: Some(proxy::BUILD_RS_TEMPLATE.to_string()),
        proxy_def: Some(def),
    }
}

fn generate_sideload(opts: &GenOpts, exports: &[Export], package_name: &str) -> GeneratedProject {
    let hijack_fn = hijack_fn_src(&opts.hijack_export, "payload");
    let lib_rs = sideload::LIB_RS_TEMPLATE.replace("{HIJACK_FUNCTION}", &hijack_fn);
    GeneratedProject {
        package_name: package_name.to_string(),
        cargo_toml: sideload::CARGO_TOML_TEMPLATE.replace("{PACKAGE_NAME}", package_name),
        lib_rs,
        forward_rs: forward_stubs(exports, &opts.hijack_export),
        build_rs: None,
        proxy_def: None,
    }
}

fn hijack_fn_src(export: &str, kind: &str) -> String {
    let ident = rust_ident(export);
    let export_attr = if is_rust_ident(export) {
        "#[no_mangle]".to_string()
    } else {
        format!(
            "#[no_mangle]\n#[export_name = \"{}\"]",
            rust_string_escape(export)
        )
    };
    let used = kind != "payload";
    let args = hijack_args(used);
    let body = if used {
        "    dispatch_call(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20)".to_string()
    } else {
        "    payload_execution();\n    1".to_string()
    };
    format!(
        "{export_attr}\npub unsafe extern \"system\" fn {ident}(\n{args}\n) -> u64 {{\n{body}\n}}"
    )
}

fn forward_stubs(exports: &[Export], hijack: &str) -> String {
    let mut out = String::new();
    for exp in exports {
        let Some(name) = exp.name.as_deref() else {
            continue;
        };
        if name == hijack {
            continue;
        }
        let ident = rust_ident(name);
        if is_rust_ident(name) {
            out.push_str(&format!(
                "#[no_mangle]\npub unsafe extern \"system\" fn {ident}() {{}}\n\n"
            ));
        } else {
            out.push_str(&format!(
                "#[no_mangle]\n#[export_name = \"{}\"]\npub unsafe extern \"system\" fn {ident}() {{}}\n\n",
                rust_string_escape(name)
            ));
        }
    }
    out
}

pub fn write_project(root: &Path, project: &GeneratedProject) -> io::Result<()> {
    if root.exists() {
        fs::remove_dir_all(root)?;
    }
    fs::create_dir_all(root.join("src"))?;
    fs::write(root.join("Cargo.toml"), project.cargo_toml.trim_start())?;
    fs::write(root.join("src").join("lib.rs"), project.lib_rs.trim_start())?;
    fs::write(root.join("src").join("forward.rs"), &project.forward_rs)?;
    if let Some(build) = &project.build_rs {
        fs::write(root.join("build.rs"), build.trim_start())?;
    }
    if let Some(def) = &project.proxy_def {
        fs::write(root.join("proxy.def"), def)?;
    }
    Ok(())
}

pub fn hijack_present(exports: &[Export], hijack: &str) -> bool {
    exports.iter().any(|e| e.name.as_deref() == Some(hijack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::Export;

    fn sample_exports() -> Vec<Export> {
        vec![
            Export {
                name: Some("BuildOtlCache".into()),
                ordinal: 1,
            },
            Export {
                name: Some("ShapingCreateFontCacheData".into()),
                ordinal: 12,
            },
            Export {
                name: Some("?Mangle@@YAXXZ".into()),
                ordinal: 3,
            },
            Export {
                name: None,
                ordinal: 7,
            },
        ]
    }

    fn proxy_opts(absolute: bool) -> GenOpts {
        GenOpts {
            mode: Mode::Proxy,
            dll_path: if absolute {
                PathBuf::from(r"C:\Windows\System32\TextShaping.dll")
            } else {
                PathBuf::from("TextShaping.dll")
            },
            dll_stem: "TextShaping".into(),
            hijack_export: "ShapingCreateFontCacheData".into(),
            original_dll_name: "Shaping.dll".into(),
            absolute,
        }
    }

    #[test]
    fn proxy_uses_crates_io_dyncvoke() {
        let p = generate(&proxy_opts(false), &sample_exports());
        assert!(
            p.cargo_toml.contains("dyncvoke = \"0.1\""),
            "{}",
            p.cargo_toml
        );
        assert!(!p.cargo_toml.contains("git ="));
        assert!(!p.cargo_toml.contains("github.com"));
        assert!(!p.cargo_toml.contains("windres"));
        assert!(!p.cargo_toml.contains("lazy_static"));
    }

    #[test]
    fn proxy_ntcreatethreadex_has_real_handle() {
        let p = generate(&proxy_opts(false), &sample_exports());
        assert!(p.lib_rs.contains("let mut thread: *mut c_void"));
        assert!(p.lib_rs.contains("&mut thread as *mut *mut c_void"));
        assert!(!p
            .lib_rs
            .contains("let thread_handle: *mut HANDLE = ptr::null_mut()"));
        assert!(p.lib_rs.contains("syscall!"));
        assert!(p.lib_rs.contains("NtCreateThreadEx"));
        assert!(p.lib_rs.contains("payload_thread"));
        assert!(p.lib_rs.contains(".to_string()"));
        assert!(p.lib_rs.contains("load_library_a(&dll)"));
    }

    #[test]
    fn proxy_def_relative_and_absolute() {
        let rel = generate(&proxy_opts(false), &sample_exports());
        let def = rel.proxy_def.unwrap();
        assert!(def.contains("BuildOtlCache=Shaping.BuildOtlCache @1"));
        assert!(def.contains("ShapingCreateFontCacheData @12"));
        assert!(!def.contains("ShapingCreateFontCacheData=Shaping"));
        assert!(def.contains("ord_7=Shaping.#7 @7 NONAME"));

        let abs = generate(&proxy_opts(true), &sample_exports());
        let def = abs.proxy_def.unwrap();
        assert!(def.contains(r"C:\Windows\System32\TextShaping.BuildOtlCache"));
        assert!(abs
            .lib_rs
            .contains(r"C:\\Windows\\System32\\TextShaping.dll"));
    }

    #[test]
    fn mangle_export_gets_export_name() {
        let p = generate(&proxy_opts(false), &sample_exports());
        assert!(p.forward_rs.contains("#[export_name = \"?Mangle@@YAXXZ\"]"));
        assert!(!p.forward_rs.contains("fn ?Mangle"));
    }

    #[test]
    fn sideload_messageboxa_nul() {
        let opts = GenOpts {
            mode: Mode::Sideload,
            dll_path: PathBuf::from("libvlc.dll"),
            dll_stem: "libvlc".into(),
            hijack_export: "libvlc_new".into(),
            original_dll_name: "libvlc_orig.dll".into(),
            absolute: false,
        };
        let p = generate(&opts, &sample_exports());
        assert!(!p.cargo_toml.contains("dyncvoke"));
        assert!(p.lib_rs.contains("MessageBoxA"));
        assert!(!p.lib_rs.contains("MessageBoxW"));
        assert!(!p.lib_rs.contains("pub unsafe extern \"system\" fn DllMain"));
        assert!(p.lib_rs.contains("Successfully!\\0"));
        assert!(p.lib_rs.contains("fn libvlc_new"));
        assert!(p.build_rs.is_none());
        assert!(p.proxy_def.is_none());
    }

    #[test]
    fn writes_tree() {
        let dir = std::env::temp_dir().join(format!(
            "lazydll-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let p = generate(&proxy_opts(false), &sample_exports());
        write_project(&dir, &p).unwrap();
        assert!(dir.join("Cargo.toml").exists());
        assert!(dir.join("src/lib.rs").exists());
        assert!(dir.join("src/forward.rs").exists());
        assert!(dir.join("build.rs").exists());
        assert!(dir.join("proxy.def").exists());
        let cargo = fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("dyncvoke = \"0.1\""));
        let _ = fs::remove_dir_all(&dir);
    }
}
