use std::process::Command;

fn run() {
    let _ = Command::new("echo").arg("hello").status();
}
