#![feature(exit_status_error)]
use std::{env, io::prelude::*};

fn run_and_get_output(code: &str, args: &[String]) -> String {
    // set by Cargo
    let bin = env!("CARGO_BIN_EXE_qrun");
    let mut child = std::process::Command::new(&bin)
        .arg("-")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(code.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    // Forward stdout
    let stdout = String::from_utf8(output.stdout).unwrap();
    print!("{}", stdout);

    // ...and then panic on failure
    output.status.exit_ok().unwrap();

    stdout
}

#[test]
fn run() {
    let code = r#"
		mov x0, #1
		mov x1, #2
		add x2, x0, x1

		cmp x2, #3
		b.ne 1f

		ret

	1:
		hlt #1
	"#;
    run_and_get_output(code, &[]);
}
