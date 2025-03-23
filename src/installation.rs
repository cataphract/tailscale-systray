use std::{fs::File, io::Write, os::unix::ffi::OsStrExt, path::PathBuf};

use anyhow::Context;
use log::{info, warn};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "icons/"]
struct Icons;

pub fn local_install() -> anyhow::Result<()> {
    install_icons()?;
    install_desktop()?;
    install_autostart()?;

    Ok(())
}

fn install_icons() -> anyhow::Result<()> {
    let prefix = PathBuf::from(std::env::var("HOME").expect("$HOME is not defined"));

    let icons = prefix.join(".local/share/icons/hicolor/scalable/apps");

    std::fs::create_dir_all(&icons)
        .with_context(|| format!("Failed to create directory: {:?}", icons))?;

    for icon in Icons::iter() {
        let icon_relpath = PathBuf::from(icon.to_string());
        if icon_relpath.extension().is_none() {
            continue;
        }
        let icon_file = Icons::get(&icon).unwrap();
        let icon_path = icons.join(icon_relpath.file_name().expect("Icon file has file name"));
        let icon_data = icon_file.data;

        std::fs::write(&icon_path, icon_data)
            .with_context(|| format!("Failed to write icon to: {:?}", icon_path))?;
        info!("Installed icon: {:?}", icon_path);
    }

    let update_cmd = std::process::Command::new("xdg-icon-resource")
        .arg("forceupdate")
        .output();
    if let Ok(output) = update_cmd {
        if output.status.success() {
            info!("Icon cache updated");
        } else {
            warn!("Failed to update icon cache");
        }
    } else {
        warn!("Failed to run xdg-icon-resource");
    }

    Ok(())
}

fn install_desktop() -> anyhow::Result<()> {
    let prefix = xdg_data_home();
    let applications = prefix.join("applications");

    std::fs::create_dir_all(&applications)
        .with_context(|| format!("Failed to create directory: {:?}", applications))?;

    let desktop_file = applications.join("tailscale-systray.desktop");

    let mut file = File::create(&desktop_file)
        .with_context(|| format!("Failed to create desktop file: {:?}", desktop_file))?;

    file.write_all(
        br#"
[Desktop Entry]
Type=Application
Name=Tailscale Systray
Comment=A tailscale indicator (using StatusNotifierItem)
Exec="#,
    )?;

    let exe = std::env::current_exe().with_context(|| "Failed to get current executable path")?;
    file.write_all(exe.as_os_str().as_bytes())?;

    file.write_all(
        br#"
Icon=network-vpn
Terminal=false
Categories=Network;Utility;
StartupNotify=false
"#,
    )?;

    info!("Installed desktop file: {:?}", desktop_file);

    Ok(())
}

fn install_autostart() -> anyhow::Result<()> {
    let autostart_dir = xdg_config_home().join("autostart");
    std::fs::create_dir_all(&autostart_dir)
        .with_context(|| format!("Failed to create directory: {:?}", autostart_dir))?;

    let autostart_file = autostart_dir.join("tailscale-systray.desktop");

    std::os::unix::fs::symlink(
        xdg_data_home().join("applications/tailscale-systray.desktop"),
        &autostart_file,
    )
    .with_context(|| format!("Failed to create symlink: {:?}", autostart_file))?;

    info!("Installed autostart symlink: {:?}", autostart_file);

    Ok(())
}

fn xdg_config_home() -> PathBuf {
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

fn xdg_data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .filter(|os_str| !os_str.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").expect("Neither XDG_DATA_HOME nor HOME is set"))
                .join(".local/share")
        })
}
