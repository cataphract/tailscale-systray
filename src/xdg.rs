use std::path::PathBuf;

/// Get XDG_CONFIG_HOME directory
/// Returns $XDG_CONFIG_HOME or $HOME/.config
pub fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|os_str| !os_str.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                std::env::var_os("HOME").expect("Neither XDG_CONFIG_HOME nor HOME is set"),
            )
            .join(".config")
        })
}

/// Get XDG_DATA_HOME directory
/// Returns $XDG_DATA_HOME or $HOME/.local/share
pub fn data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .filter(|os_str| !os_str.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").expect("Neither XDG_DATA_HOME nor HOME is set"))
                .join(".local/share")
        })
}

/// Get application-specific data directory
/// Creates the directory if it doesn't exist
pub fn app_data_dir(app_name: &str) -> anyhow::Result<PathBuf> {
    let app_dir = data_home().join(app_name);

    if !app_dir.exists() {
        std::fs::create_dir_all(&app_dir)?;
    }

    Ok(app_dir)
}

/// Get application-specific config directory
/// Creates the directory if it doesn't exist
#[allow(dead_code)]
pub fn app_config_dir(app_name: &str) -> anyhow::Result<PathBuf> {
    let app_dir = config_home().join(app_name);

    if !app_dir.exists() {
        std::fs::create_dir_all(&app_dir)?;
    }

    Ok(app_dir)
}
