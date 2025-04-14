use anyhow::Context;
use log::{debug, warn};
use std::fs;
use std::path::PathBuf;

use crate::xdg;

const APP_NAME: &str = "tailscale-systray";
const HISTORY_FILE: &str = "command-history.txt";
const MAX_HISTORY: usize = 10;

fn history_file_path() -> anyhow::Result<PathBuf> {
    let app_dir =
        xdg::app_data_dir(APP_NAME).context("Failed to get application data directory")?;

    Ok(app_dir.join(HISTORY_FILE))
}

pub fn load_history() -> Vec<String> {
    match history_file_path() {
        Ok(path) => {
            if !path.exists() {
                debug!("History file does not exist yet: {:?}", path);
                return Vec::new();
            }

            match fs::read_to_string(&path) {
                Ok(content) => {
                    let history: Vec<String> = content
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    debug!("Loaded {} commands from history", history.len());
                    history
                }
                Err(e) => {
                    warn!("Failed to read history file: {}", e);
                    Vec::new()
                }
            }
        }
        Err(e) => {
            warn!("Failed to get history file path: {}", e);
            Vec::new()
        }
    }
}

fn save_history<'a, T, S>(history: T) -> anyhow::Result<()>
where
    T: Iterator<Item = &'a S> + DoubleEndedIterator + ExactSizeIterator,
    S: AsRef<str> + 'a,
{
    let path = history_file_path()?;

    let to_save: Vec<&str> = history
        .rev()
        .take(MAX_HISTORY)
        .rev()
        .map(|s| s.as_ref())
        .collect();

    let content = to_save.join("\n");
    fs::write(&path, content).with_context(|| format!("Failed to write history to {:?}", path))?;

    debug!("Saved {} commands to history", to_save.len());
    Ok(())
}

pub fn add_to_history(command: &str) {
    let mut history = load_history();

    // Remove duplicate if it exists
    history.retain(|cmd| cmd != command);

    // Add to the end
    history.push(command.to_string());

    if let Err(e) = save_history(history.iter()) {
        warn!("Failed to save command history: {}", e);
    }
}

pub fn get_recent_commands() -> Vec<String> {
    let history = load_history();
    history.into_iter().rev().take(MAX_HISTORY).collect()
}
