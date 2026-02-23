use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub fn print_success(msg: &str) {
    println!("{} {}", console::style("✓").green().bold(), msg);
}

#[allow(dead_code)]
pub fn print_error(msg: &str) {
    eprintln!("{} {}", console::style("✗").red().bold(), msg);
}

#[allow(dead_code)]
pub fn print_warning(msg: &str) {
    eprintln!("{} {}", console::style("⚠").yellow().bold(), msg);
}

pub fn print_info(msg: &str) {
    println!("{} {}", console::style("ℹ").blue().bold(), msg);
}
