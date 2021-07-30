#![feature(exit_status_error)]
use anyhow::{Context, Result};
use clap::{ArgEnum, Clap};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    env,
    io::prelude::*,
    path::{Path, PathBuf},
};
use unicorn::Cpu;

#[derive(ArgEnum, PartialEq)]
enum Lang {
    /// Rust.
    Rust,
    /// Rust `global_asm!`.
    RustAsm,
}

#[derive(Clap)]
struct Opts {
    /// Be more verbose; can be used multiple times
    ///
    /// Alternatively, you can pass a log level by a `QRUN_LOG` environment
    /// variable.
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
    #[clap(long, short, default_value = "aarch64-unknown-none")]
    target: String,
    #[clap(short = 'x', arg_enum, default_value = "rust-asm")]
    lang: Lang,
    source: PathBuf,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let default_log_level = [log::Level::Info, log::Level::Debug, log::Level::Trace]
        .get(opts.verbose)
        .ok_or_else(|| anyhow::anyhow!("too many `--verbose`s"))?;
    env_logger::Builder::from_env(
        env_logger::Env::new().filter_or("QRUN_LOG", format!("qrun={}", default_log_level)),
    )
    .init();

    let rustc = env::var_os("RUSTC");
    let rustc = rustc.unwrap_or("rustc".into());

    let rust_src_file: Box<dyn CowFile + '_>;

    match opts.lang {
        Lang::Rust => {
            rust_src_file = argpath_to_cow_file(&opts.source)?;
        }
        Lang::RustAsm => {
            let asm = argpath_read_to_string(&opts.source)?;

            // How many `#`s are required to enclose `asm` without escaping?
            let num_wrappers = asm
                .bytes()
                .fold((0usize, 0usize), |(max, cur), b| {
                    let new_cur = if b == b'#' {
                        cur.checked_add(1)
                            .expect("The input source code includes too many consecutive `#`s")
                    } else {
                        1
                    };
                    (max.max(new_cur), new_cur)
                })
                .0;
            let wrapper = "#".repeat(num_wrappers);
            let rust_src = include_str!("rasm_template.rs")
                .replace("###", &wrapper)
                .replace("{code}", &asm);

            rust_src_file = Box::new(temp_path_initialized(rust_src.as_bytes())?);
        }
    }

    let elf_file_path = tempfile::NamedTempFile::new()
        .context("Could not create a temporary file")?
        .into_temp_path();

    let linker_script_path = temp_path_initialized(include_bytes!("link.ld"))?;

    std::process::Command::new(&rustc)
        .arg("-Copt-level=3")
        .arg("--crate-type=bin")
        .arg("--crate-name=qrun")
        .arg("--target")
        .arg(&opts.target)
        .arg(format!(
            "-Clink-arg={}",
            linker_script_path
                .to_str()
                .context("Temporary file path is unrepresentable in UTF-8")?
        ))
        .arg("-o")
        .arg(&*elf_file_path)
        .arg(rust_src_file.path())
        .spawn()
        .context("Could not execute the Rust compiler")?
        .wait()
        .unwrap()
        .exit_ok()
        .context("The Rust compiler failed")?;

    // Create the machine
    let emu = unicorn::CpuARM64::new(unicorn::Mode::LITTLE_ENDIAN).unwrap();

    // Open the compiled image
    let elf_file =
        std::fs::File::open(&elf_file_path).with_context(|| "Failed to open the compiled file")?;

    // Safety: It's read-only CoW mapping, so it should be safe to map as `&[u8]`
    let mmap = unsafe {
        memmap2::MmapOptions::default()
            .populate()
            .map_copy_read_only(&elf_file)
            .context("Failed to mmap the compiled file")?
    };
    let elf = goblin::elf::Elf::parse(&mmap).context("Could not parse the compiled file")?;

    // Find the entry point, etc.
    let mut entry_va = None;
    let mut stack_start_va = None;
    let mut ram_start_va = None;
    let mut ram_end_va = None;
    for sym in elf.syms.iter() {
        let name = if let Some(x) = elf.strtab.get_at(sym.st_name) {
            x
        } else {
            continue;
        };

        log::trace!("Found symbol {:?} at {:#x}", name, sym.st_value);

        match name {
            "main" => {
                log::debug!("Found `main` at {:#x}", sym.st_value);
                entry_va = Some(sym.st_value);
            }
            "_stack_start" => {
                log::debug!("Found `_stack_start` at {:#x}", sym.st_value);
                stack_start_va = Some(sym.st_value);
            }
            "_ram_start" => {
                log::debug!("Found `_ram_start` at {:#x}", sym.st_value);
                ram_start_va = Some(sym.st_value);
            }
            "_ram_end" => {
                log::debug!("Found `_ram_end` at {:#x}", sym.st_value);
                ram_end_va = Some(sym.st_value);
            }
            _ => {}
        }
    }

    let entry_va =
        entry_va.context("Could not find an entry point. Please define a symbol named `main`")?;
    let ram_start_va = ram_start_va.context("Could not find `_ram_start`")?;
    let ram_end_va = ram_end_va.context("Could not find `_ram_end`")?;

    // Map memory (`unicorn` demands 4KB alignment)
    const PAGE_SHIFT: u32 = 12;
    let mut pagemap = BTreeMap::<u64, unicorn::Protection>::new();
    for phdr in elf.program_headers.iter() {
        log::debug!("Processing segment {:?} for allocating pages", phdr);
        if phdr.p_memsz == 0 {
            log::debug!(".. Ignoring this segment because `p_filesz` is zero.");
            continue;
        }
        let start = phdr.p_vaddr >> PAGE_SHIFT;
        let end = (phdr.p_vaddr + phdr.p_memsz - 1) >> PAGE_SHIFT;
        let mut prot = unicorn::Protection::empty();
        if phdr.p_flags & (goblin::elf::program_header::PF_R) != 0 {
            prot |= unicorn::Protection::READ;
        }
        if phdr.p_flags & (goblin::elf::program_header::PF_W) != 0 {
            prot |= unicorn::Protection::WRITE;
        }
        if phdr.p_flags & (goblin::elf::program_header::PF_X) != 0 {
            prot |= unicorn::Protection::EXEC;
        }

        log::debug!(
            "Mapping {:#x}..={:#x} as {:?} for an ELF segment",
            start << PAGE_SHIFT,
            (end << PAGE_SHIFT) + ((1 << PAGE_SHIFT) - 1),
            prot
        );

        for i in start..=end {
            *pagemap.entry(i).or_insert(unicorn::Protection::empty()) |= prot;
        }
    }

    log::debug!(
        "Mapping {:#x}..={:#x} for variable storage",
        ram_start_va,
        ram_end_va - 1
    );
    for i in ram_start_va >> PAGE_SHIFT..ram_end_va >> PAGE_SHIFT {
        *pagemap.entry(i).or_insert(unicorn::Protection::empty()) |=
            unicorn::Protection::READ | unicorn::Protection::WRITE;
    }

    {
        let mut it = pagemap.iter().peekable();
        while let Some((&page_i, &prot)) = it.next() {
            // Look for consecutive pages with the same attributes
            let start = page_i;
            let mut end = page_i;
            let mut len = 1usize << PAGE_SHIFT;
            while let Some(&(&page_i, &prot2)) = it.peek() {
                let new_len = if let Some(new_len) = len.checked_add(1 << PAGE_SHIFT) {
                    new_len
                } else {
                    break;
                };

                if page_i != end + 1 || prot != prot2 {
                    break;
                }

                end = page_i;
                len = new_len;
                it.next();
            }

            let start = start << PAGE_SHIFT;

            emu.mem_map(start, len, prot)
                .map_err(fix_unicorn_err)
                .with_context(|| {
                    format!(
                        "Could not map {:#x} bytes starting from address {:#x} as {:?}",
                        start, len, prot
                    )
                })?;
        }
    }

    // Load the compiled program
    for phdr in elf.program_headers.iter() {
        log::debug!("Processing segment {:?} for mapping", phdr);
        if phdr.p_filesz == 0 {
            log::debug!(".. Ignoring this segment because `p_filesz` is zero.");
            continue;
        }

        (|| {
            let file_start = usize::try_from(phdr.p_offset)
                .ok()
                .context("Invalid file offset")?;
            let file_len = usize::try_from(phdr.p_filesz)
                .ok()
                .context("Invalid file offset")?;
            let file_end = file_start
                .checked_add(file_len)
                .context("Invalid file offset")?;

            log::trace!(
                "(file_start, file_len, file_end) = ({:#x}, {:#x}, {:#x})",
                file_start,
                file_len,
                file_end,
            );

            log::debug!(
                "Loading file[{:?}] to address {:#x}..={:#x}",
                file_start..file_end,
                phdr.p_vaddr,
                phdr.p_vaddr + (file_len as u64 - 1),
            );

            emu.mem_write(phdr.p_vaddr, &mmap[file_start..file_end])
                .map_err(fix_unicorn_err)
                .with_context(|| format!("Could not load the segment from the compiled file"))?;

            Ok(()) as Result<()>
        })()
        .with_context(|| format!("Could not map the segment at address {:#x}", phdr.p_vaddr))?;
    }

    // Exit point (it doesn't require executable code, but the memory needs to
    // be executable)
    let exit_va = 0xe0000000;
    emu.mem_map(
        exit_va,
        1 << PAGE_SHIFT,
        unicorn::Protection::READ | unicorn::Protection::EXEC,
    )
    .unwrap();

    // Initial register values
    emu.reg_write(unicorn::RegisterARM64::LR, exit_va).unwrap();
    if let Some(va) = stack_start_va {
        emu.reg_write(unicorn::RegisterARM64::SP, va).unwrap();
    }

    let max_instr_count = 0x10000000;
    let result = emu.emu_start(entry_va, exit_va, 0, max_instr_count);

    // Dump the register
    let int_regs = &[
        ("x0", unicorn::RegisterARM64::X0),
        ("x1", unicorn::RegisterARM64::X1),
        ("x2", unicorn::RegisterARM64::X2),
        ("x3", unicorn::RegisterARM64::X3),
        ("x4", unicorn::RegisterARM64::X4),
        ("x5", unicorn::RegisterARM64::X5),
        ("x6", unicorn::RegisterARM64::X6),
        ("x7", unicorn::RegisterARM64::X7),
        ("x8", unicorn::RegisterARM64::X8),
        ("x9", unicorn::RegisterARM64::X9),
        ("x10", unicorn::RegisterARM64::X10),
        ("x11", unicorn::RegisterARM64::X11),
        ("x12", unicorn::RegisterARM64::X12),
        ("x13", unicorn::RegisterARM64::X13),
        ("x14", unicorn::RegisterARM64::X14),
        ("x15", unicorn::RegisterARM64::X15),
        ("x16", unicorn::RegisterARM64::IP1),
        ("x17", unicorn::RegisterARM64::IP0),
        ("x18", unicorn::RegisterARM64::X18),
        ("x19", unicorn::RegisterARM64::X19),
        ("x20", unicorn::RegisterARM64::X20),
        ("x21", unicorn::RegisterARM64::X21),
        ("x22", unicorn::RegisterARM64::X22),
        ("x23", unicorn::RegisterARM64::X23),
        ("x24", unicorn::RegisterARM64::X24),
        ("x25", unicorn::RegisterARM64::X25),
        ("x26", unicorn::RegisterARM64::X26),
        ("x27", unicorn::RegisterARM64::X27),
        ("x28", unicorn::RegisterARM64::X28),
        ("x29", unicorn::RegisterARM64::FP),
        ("lr", unicorn::RegisterARM64::LR),
        ("sp", unicorn::RegisterARM64::SP),
        ("pc", unicorn::RegisterARM64::PC),
    ];

    let cols = 4;
    for int_regs in int_regs.chunks(cols) {
        for (name, reg) in int_regs.iter() {
            let value = emu.reg_read(*reg).unwrap();
            print!("{:3} = {:#016x} ", name, value);
        }
        println!();
    }

    // Report execution error
    result
        .map_err(fix_unicorn_err)
        .with_context(|| format!("Execution failed"))?;

    Ok(())
}

fn fix_unicorn_err(e: unicorn::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", e)
}

/// Like `Cow<'_, str>` - you might or might not own the underlying file.
trait CowFile: 'static {
    fn path(&self) -> &Path;
}

impl CowFile for PathBuf {
    fn path(&self) -> &Path {
        self
    }
}

impl CowFile for tempfile::TempPath {
    fn path(&self) -> &Path {
        self
    }
}

/// Return `path` as a `CowFile`. If `path` is `"-"`, copy stdin to a temporary
/// file and return it.
fn argpath_to_cow_file(path: &Path) -> Result<Box<dyn CowFile + '_>> {
    if path == Path::new("-") {
        let mut tmpfile =
            tempfile::NamedTempFile::new().context("Could not create a temporary file")?;
        std::io::copy(&mut std::io::stdin().lock(), tmpfile.as_file_mut())
            .context("Could not copy the input from stdin to a temporary file")?;
        Ok(Box::new(tmpfile.into_temp_path()))
    } else {
        Ok(Box::new(path.to_owned()))
    }
}

fn temp_path_initialized(data: &[u8]) -> Result<tempfile::TempPath> {
    let mut tmpfile =
        tempfile::NamedTempFile::new().context("Could not create a temporary file")?;
    tmpfile
        .as_file_mut()
        .write_all(data)
        .context("Could not write to a temporary file")?;
    Ok(tmpfile.into_temp_path())
}

/// Read `path`, handling the `"-"` case
fn argpath_read_to_string(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin()
            .lock()
            .read_to_string(&mut s)
            .context("Could not read from stdin")?;
        Ok(s)
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("Could not open {:?} for reading", path))
    }
}
