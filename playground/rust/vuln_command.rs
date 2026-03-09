use std::process::Command;

fn run(user_input: &str) {
    let cmd = format!("echo {}", user_input);
    let _ = Command::new("sh").arg("-c").arg(cmd).status();
}
