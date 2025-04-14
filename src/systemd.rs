use crate::namespaces::MNT_NS_PATH;
use crate::namespaces::NET_NS_PATH;
use anyhow::Context;
use log::info;
use std::path::{Path, PathBuf};
use zbus::Connection;

const SYSTEMD_UNIT: &str = "tailscaled.service";
const DROPIN_FILENAME: &str = "10-tailscale-systray.conf";

pub async fn install_dropin(tailscale_systray_path: &Path) -> anyhow::Result<()> {
    let connection = Connection::system()
        .await
        .context("Failed to connect to D-Bus system bus")?;

    if !unit_exists(&connection, SYSTEMD_UNIT).await? {
        anyhow::bail!("Systemd unit {} does not exist", SYSTEMD_UNIT);
    }

    let override_path = unit_override_path(&connection, SYSTEMD_UNIT, DROPIN_FILENAME).await?;

    if override_path.exists() {
        anyhow::bail!("Override file {:?} already exists", override_path);
    }

    info!(
        "Creating systemd drop-in configuration for {} in {:?}",
        SYSTEMD_UNIT, override_path
    );

    let config =
        generate_namespace_override(&connection, SYSTEMD_UNIT, tailscale_systray_path).await?;

    let parent_dir = override_path
        .parent()
        .context("Failed to get parent directory of override path")?;
    std::fs::create_dir_all(parent_dir).context("Failed to create override directory")?;

    info!("Ensured directory exists: {:?}", parent_dir);

    std::fs::write(&override_path, config)
        .with_context(|| format!("Failed to write override file {}", override_path.display()))?;

    info!(
        "Created systemd drop-in configuration at {}",
        override_path.display()
    );

    reload_and_restart(&connection, SYSTEMD_UNIT).await?;
    Ok(())
}

pub async fn uninstall_dropin() -> anyhow::Result<()> {
    let connection = Connection::system()
        .await
        .context("Failed to connect to D-Bus system bus")?;

    if !unit_exists(&connection, SYSTEMD_UNIT).await? {
        anyhow::bail!("Systemd unit {} does not exist", SYSTEMD_UNIT);
    }

    let override_path = unit_override_path(&connection, SYSTEMD_UNIT, DROPIN_FILENAME).await?;

    if !override_path.exists() {
        anyhow::bail!("Override file {:?} does not exist", override_path);
    }

    info!(
        "Removing systemd drop-in configuration from {:?}",
        override_path
    );

    std::fs::remove_file(&override_path)
        .with_context(|| format!("Failed to remove override file {}", override_path.display()))?;

    info!(
        "Removed systemd drop-in configuration at {}",
        override_path.display()
    );

    reload_and_restart(&connection, SYSTEMD_UNIT).await?;
    Ok(())
}

/// Check if tailscaled.service exists on this system
pub async fn tailscaled_service_exists() -> bool {
    let connection = match Connection::system().await {
        Ok(conn) => conn,
        Err(_) => return false,
    };

    unit_exists(&connection, SYSTEMD_UNIT)
        .await
        .unwrap_or(false)
}

/// Check if tailscaled is running in our isolated namespace by examining its ExecStart
pub async fn is_running_in_namespace() -> anyhow::Result<bool> {
    let connection = Connection::system().await?;

    let exec_start = get_exec_start(&connection, SYSTEMD_UNIT)
        .await
        .with_context(|| "Failed to get ExecStart command")?;

    // Check if it contains nsenter with our namespace paths
    Ok(exec_start.contains("nsenter")
        && exec_start.contains("--net=")
        && exec_start.contains(NET_NS_PATH))
}

/// Get the main PID of the tailscaled service
pub async fn get_tailscaled_pid() -> anyhow::Result<u32> {
    let connection = Connection::system().await?;

    // Get the unit's object path
    let msg = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnit",
            &(SYSTEMD_UNIT),
        )
        .await
        .context("Failed to get unit from systemd")?;

    let unit_path: zbus::zvariant::OwnedObjectPath = msg
        .body()
        .deserialize()
        .context("Failed to deserialize unit path")?;

    // Get the MainPID property
    let msg = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            &unit_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.systemd1.Service", "MainPID"),
        )
        .await
        .context("Failed to get MainPID property")?;

    let body = msg.body();
    let variant: zbus::zvariant::Value = body
        .deserialize()
        .context("Failed to deserialize MainPID")?;

    let pid: u32 = variant
        .try_into()
        .context("Failed to convert MainPID to u32")?;

    if pid == 0 {
        anyhow::bail!("Service {} is not running (MainPID is 0)", SYSTEMD_UNIT);
    }

    Ok(pid)
}

async fn unit_exists(connection: &Connection, unit_name: &str) -> anyhow::Result<bool> {
    // call the GetUnit method on the systemd Manager interface
    let result = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnit",
            &(unit_name),
        )
        .await;

    match result {
        Ok(_msg) => {
            // If GetUnit succeeds, the unit exists
            Ok(true)
        }
        Err(e) => {
            // check if this is a "NoSuchUnit" error
            if let zbus::Error::MethodError(name, _, _) = &e {
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" {
                    return Ok(false);
                }
            }
            // any other error is a real error
            Err(e).context("Failed to query systemd for unit")
        }
    }
}

async fn unit_override_path(
    connection: &Connection,
    unit_name: &str,
    dropin_filename: &str,
) -> anyhow::Result<PathBuf> {
    // get the UnitPath property to find systemd's unit search paths
    let msg = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.systemd1.Manager", "UnitPath"),
        )
        .await
        .context("Failed to get UnitPath property")?;

    let body = msg.body();
    let variant: zbus::zvariant::Value = body
        .deserialize()
        .context("Failed to deserialize UnitPath")?;
    let unit_paths: Vec<String> = variant
        .try_into()
        .context("Failed to convert UnitPath to Vec<String>")?;

    let override_base = unit_paths
        .iter()
        .find(|path| {
            path.contains("/lib/") && !path.contains("control") && !path.contains("attached")
        })
        .context("Could not find suitable override directory in UnitPath")?;

    // override path is <base>/<unit>.d/override.conf
    Ok(PathBuf::from(override_base)
        .join(format!("{}.d", unit_name))
        .join(dropin_filename))
}

async fn get_exec_start(connection: &Connection, unit_name: &str) -> anyhow::Result<String> {
    // Get the unit's object path
    let msg = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "GetUnit",
            &(unit_name),
        )
        .await
        .context("Failed to get unit from systemd")?;

    let unit_path: zbus::zvariant::OwnedObjectPath = msg
        .body()
        .deserialize()
        .context("Failed to deserialize unit path")?;

    // Get the ExecStart property
    let msg = connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            &unit_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.systemd1.Service", "ExecStart"),
        )
        .await
        .context("Failed to get ExecStart property")?;

    let body = msg.body();
    let variant: zbus::zvariant::Value = body
        .deserialize()
        .context("Failed to deserialize ExecStart")?;

    // ExecStart is an array of structures: a(sasbttttuii)
    // Each structure contains: path, argv_count, argv..., ignore_failure, timestamps, etc.
    // We extract the first element (primary command)
    let array: Vec<zbus::zvariant::Structure> = variant
        .try_into()
        .context("Failed to convert ExecStart to array")?;

    if array.is_empty() {
        anyhow::bail!("ExecStart is empty for unit {}", unit_name);
    }

    // get the first command (index 0)
    let exec_start_struct = &array[0];
    let fields = exec_start_struct.fields();

    if fields.len() < 2 {
        anyhow::bail!("ExecStart structure has insufficient fields");
    }

    // Field 0: path (string)
    // Field 1: argv (array of strings)
    let argv: Vec<String> = fields[1]
        .try_clone()
        .context("Failed to clone argv field")?
        .try_into()
        .context("Failed to convert argv to Vec<String>")?;

    // Join the argv array into a command string
    // Quote arguments that contain spaces or special characters
    let command = argv
        .iter()
        .map(|arg| {
            if arg.contains(' ') || arg.contains('$') || arg.contains('"') {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    Ok(command)
}

/// This creates a drop-in configuration that:
/// 1. Runs `tailscale-systray ns-prepare` before starting tailscaled
/// 2. Wraps tailscaled execution with nsenter to use the isolated network and mount namespaces
async fn generate_namespace_override(
    connection: &Connection,
    unit_name: &str,
    tailscale_systray_path: &Path,
) -> anyhow::Result<String> {
    let systray_bin = tailscale_systray_path
        .to_str()
        .context("Non-unicode systray path")?;
    let original_command = get_exec_start(connection, unit_name).await?;

    Ok(format!(
        r#"[Unit]
# Setup isolated namespaces before starting tailscaled
# This allows tailscale to run in a segregated network environment

[Service]
# Prepare the network and mount namespaces
ExecStartPre={systray_bin} ns-prepare

# Clear the original ExecStart
ExecStart=

# Run tailscaled inside the isolated namespaces
ExecStart=nsenter --net={NET_NS_PATH} --mount={MNT_NS_PATH} {original_command}
"#
    ))
}

async fn reload_and_restart(connection: &Connection, unit_name: &str) -> anyhow::Result<()> {
    info!("Reloading systemd daemon configuration");
    connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "Reload",
            &(),
        )
        .await
        .context("Failed to reload systemd daemon")?;

    info!("Successfully reloaded systemd daemon");

    // Restart the tailscaled service
    // RestartUnit takes (unit_name, mode) where mode is typically "replace"
    info!("Restarting {} service", unit_name);
    connection
        .call_method(
            Some("org.freedesktop.systemd1"),
            "/org/freedesktop/systemd1",
            Some("org.freedesktop.systemd1.Manager"),
            "RestartUnit",
            &(unit_name, "replace"),
        )
        .await
        .context("Failed to restart tailscaled service")?;

    info!("Successfully restarted {} service", unit_name);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connection() -> Connection {
        Connection::system()
            .await
            .expect("Failed to connect to system bus")
    }

    #[tokio::test]
    async fn test_unit_exists() {
        let conn = connection().await;
        // tailscaled.service may or may not exist, but this should not error
        let exists = unit_exists(&conn, SYSTEMD_UNIT).await;
        assert!(exists.is_ok());

        // A unit that definitely doesn't exist
        let exists = unit_exists(&conn, "this-unit-definitely-does-not-exist.service").await;
        assert!(exists.is_ok());
        assert!(!exists.unwrap());
    }

    #[tokio::test]
    async fn test_unit_override_path() {
        let conn = connection().await;
        let path = unit_override_path(&conn, SYSTEMD_UNIT, DROPIN_FILENAME)
            .await
            .expect("Failed to get override path");
        // Should contain the unit name and drop-in filename
        assert!(path.to_string_lossy().contains(SYSTEMD_UNIT));
        assert!(path.to_string_lossy().contains(DROPIN_FILENAME));
        // Should be in a .d directory
        assert!(path.to_string_lossy().contains(".d"));
    }

    #[tokio::test]
    async fn test_get_exec_start() {
        let conn = connection().await;
        // Only run this test if tailscaled.service exists
        if unit_exists(&conn, SYSTEMD_UNIT).await.unwrap_or(false) {
            let exec_start = get_exec_start(&conn, SYSTEMD_UNIT)
                .await
                .expect("Failed to get ExecStart");
            // Should contain something
            assert!(!exec_start.is_empty());
            // Should likely contain tailscaled
            // (might not if the unit is heavily customized)
        }
    }

    #[tokio::test]
    async fn test_generate_namespace_override() {
        let conn = connection().await;
        // Only run this test if tailscaled.service exists
        if unit_exists(&conn, SYSTEMD_UNIT).await.unwrap_or(false) {
            let override_content = generate_namespace_override(
                &conn,
                SYSTEMD_UNIT,
                Path::new("/usr/local/bin/tailscale-systray"),
            )
            .await
            .expect("Failed to generate override");

            // Should contain key elements
            assert!(override_content.contains("ExecStartPre="));
            assert!(override_content.contains("ns-prepare"));
            assert!(override_content.contains("nsenter"));
            assert!(override_content.contains(NET_NS_PATH));
            assert!(override_content.contains(MNT_NS_PATH));
        }
    }
}
