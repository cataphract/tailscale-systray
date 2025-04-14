use std::{
    cell::Cell,
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    str::FromStr,
    thread,
};

use arboard::Clipboard;
use clap::{Parser, Subcommand};
use ksni::{
    menu::{CheckmarkItem, StandardItem},
    Tray, TrayMethods,
};
use log::{debug, error, info, trace, warn, LevelFilter};
use nix::unistd::getpid;
use notify_rust::Notification;
use ns_launcher::NamespaceLauncher;
use std::io::{IsTerminal, Write};
use tailscale::{ExitNodeOption, TailscaleExec, TailscalePrefs, TailscaleStatus};

mod command_history;
mod installation;
mod namespaces;
mod ns_launcher;
mod systemd;
mod tailscale;
mod xdg;

#[derive(Debug)]
enum ServiceState {
    Down,
    Running(Box<TailscaleStatus>),
}
struct TailscaleTray {
    exec: TailscaleExec,
    status: ServiceState,
    prefs: Option<Box<TailscalePrefs>>,
    clipboard: Clipboard,
    has_systemd_service: bool,
    in_namespace: bool,
}
impl TailscaleTray {
    async fn new(
        tailscale_bin: &Path,
        socket: &Option<PathBuf>,
        up_arg: &[OsString],
        has_systemd_service: bool,
    ) -> Self {
        let exec = TailscaleExec::new(tailscale_bin.into(), socket.as_ref(), up_arg.into());
        let status = TailscaleTray::fetch_status(&exec);
        let prefs = match status {
            ServiceState::Running(_) => TailscaleTray::fetch_prefs(&exec),
            _ => None,
        };

        let in_namespace = has_systemd_service && Self::fetch_namespace_status().await;

        Self {
            exec,
            status,
            prefs,
            clipboard: Clipboard::new().unwrap(),
            has_systemd_service,
            in_namespace,
        }
    }

    fn fetch_status(exec: &TailscaleExec) -> ServiceState {
        trace!("Fetching Tailscale status");
        exec.status()
            .map(|s| ServiceState::Running(Box::new(s)))
            .unwrap_or_else(|e| {
                warn!("Failed to fetch Tailscale status: {:#}", e);
                ServiceState::Down
            })
    }

    fn fetch_prefs(exec: &TailscaleExec) -> Option<Box<TailscalePrefs>> {
        trace!("Fetching Tailscale preferences");
        match exec.prefs() {
            Ok(prefs) => Some(Box::new(prefs)),
            Err(e) => {
                warn!("Failed to fetch Tailscale preferences: {:#}", e);
                None
            }
        }
    }

    fn refetch_status(&mut self) {
        debug!("Refreshing Tailscale status and preferences");
        self.status = Self::fetch_status(&self.exec);
        self.prefs = match &self.status {
            ServiceState::Running(_) => Self::fetch_prefs(&self.exec),
            _ => None,
        };
        debug!("Refreshed status: {:?}", self.status);
    }

    fn set_namespace_status(&mut self, in_namespace: bool) {
        self.in_namespace = in_namespace;
    }

    pub async fn fetch_namespace_status() -> bool {
        systemd::is_running_in_namespace()
            .await
            .unwrap_or_else(|e| {
                warn!("Failed to determine if running in namespace: {:#}", e);
                false
            })
    }
}

impl Tray for TailscaleTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "tailscale-systray".into()
    }

    fn title(&self) -> String {
        match &self.status {
            ServiceState::Down => "Tailscale Down".into(),
            ServiceState::Running(status) => {
                let msg = if status.health.is_empty() {
                    "Healthy".into()
                } else {
                    status.health.join(", ")
                };
                format!("Tailscale: {}", msg)
            }
        }
    }

    fn icon_name(&self) -> String {
        match &self.status {
            ServiceState::Down => "tailscale-down",
            ServiceState::Running(status) => {
                if status.self_node.online {
                    if status.exit_node_status.as_ref().is_some_and(|x| x.online) {
                        if self.in_namespace {
                            "tailscale-exit-node-ns"
                        } else {
                            "tailscale-exit-node"
                        }
                    } else if self.in_namespace {
                        "tailscale-up-ns"
                    } else {
                        "tailscale-up"
                    }
                } else {
                    "tailscale-down"
                }
            }
        }
        .into()
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;

        let first_block = || {
            let res: Vec<ksni::MenuItem<TailscaleTray>> = match self.status {
                ServiceState::Down => vec![StandardItem {
                    label: "Tailscale Service Down".into(),
                    disposition: Disposition::Alert,
                    ..Default::default()
                }
                .into()],
                ServiceState::Running(ref tstatus) => {
                    let first_ip = tstatus
                        .tailscale_ips
                        .as_ref()
                        .and_then(|ips| ips.first())
                        .cloned();
                    let mut res: Vec<ksni::MenuItem<TailscaleTray>> = vec![StandardItem {
                        label: format!(
                            "{}: {}",
                            tstatus.self_node.host_name, tstatus.backend_state
                        ),
                        activate: Box::new(move |this: &mut Self| {
                            if let Some(ip) = &first_ip {
                                match this.clipboard.set_text(ip) {
                                    Ok(_) => debug!("Copied IP {} to clipboard", ip),
                                    Err(e) => warn!("Failed to copy IP to clipboard: {}", e),
                                }
                            }
                        }),
                        ..Default::default()
                    }
                    .into()];

                    if tstatus.backend_state == "Running" {
                        res.push(
                            StandardItem {
                                label: "Disable".into(),
                                activate: Box::new(|this: &mut Self| {
                                    info!("User requested to disable Tailscale");
                                    if let Err(err) = this.exec.down() {
                                        error!("Failed to disable Tailscale: {:#}", err);
                                        notify_of_failure(&err);
                                    } else {
                                        info!("Successfully disabled Tailscale");
                                    }
                                }),
                                ..Default::default()
                            }
                            .into(),
                        );
                    } else if tstatus.backend_state == "NeedsLogin" {
                        res.push(
                            StandardItem {
                                label: "Login".into(),
                                activate: Box::new(|this: &mut Self| {
                                    info!("User requested to login to Tailscale");
                                    this.exec.login();
                                }),
                                ..Default::default()
                            }
                            .into(),
                        );
                    } else {
                        res.push(
                            StandardItem {
                                label: "Enable".into(),
                                activate: Box::new(|this: &mut Self| {
                                    info!("User requested to enable Tailscale");
                                    if let Err(err) = this.exec.up() {
                                        error!("Failed to enable Tailscale: {:#}", err);
                                        notify_of_failure(&err);
                                    } else {
                                        info!("Successfully enabled Tailscale");
                                    }
                                }),
                                ..Default::default()
                            }
                            .into(),
                        );
                    }

                    res
                }
            };
            res
        };

        let mut res: Vec<ksni::MenuItem<TailscaleTray>> = vec![];
        res.append(&mut first_block());
        res.push(MenuItem::Separator);
        if let ServiceState::Running(ref sta) = self.status {
            if sta.backend_state == "Running" {
                res.push(
                    SubMenu {
                        label: "Online peers".into(),
                        submenu: online_peers(sta),
                        ..Default::default()
                    }
                    .into(),
                );
                if let Some(prefs) = self.prefs.as_ref() {
                    res.push(
                        SubMenu {
                            label: "Exit nodes".into(),
                            submenu: exit_node_menu(sta, prefs),
                            ..Default::default()
                        }
                        .into(),
                    );
                }
            }
        }

        // Namespace management menu (only show if tailscaled.service exists)
        if self.has_systemd_service {
            res.push(MenuItem::Separator);

            if self.in_namespace {
                // Show submenu with Run... option
                res.push(
                    SubMenu {
                        label: "Namespace".into(),
                        submenu: namespace_menu(),
                        ..Default::default()
                    }
                    .into(),
                );
            } else {
                res.push(
                    StandardItem {
                        label: "Enable Namespace Isolation...".into(),
                        activate: Box::new(|_| {
                            info!("User requested to enable namespace isolation");
                            thread::spawn(enable_namespace_isolation);
                        }),
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }

        res.push(MenuItem::Separator);
        res.push(
            StandardItem {
                label: "Exit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| {
                    info!("User requested to exit the application");
                    std::process::exit(0)
                }),
                ..Default::default()
            }
            .into(),
        );
        res
    }
}

fn online_peers(status: &TailscaleStatus) -> Vec<ksni::MenuItem<TailscaleTray>> {
    trace!(
        "Building online peers menu with {} peers",
        status.online_peers().len()
    );
    status
        .online_peers()
        .iter()
        .map(|p| {
            let first_ip = p
                .tailscale_ips
                .as_ref()
                .and_then(|ips| ips.first())
                .cloned();
            StandardItem {
                label: p.host_name.clone(),
                activate: Box::new(move |this: &mut TailscaleTray| {
                    if let Some(ip) = &first_ip {
                        match this.clipboard.set_text(ip) {
                            Ok(_) => debug!("Copied peer IP {} to clipboard", ip),
                            Err(e) => warn!("Failed to copy peer IP to clipboard: {}", e),
                        }
                    }
                }),
                ..Default::default()
            }
            .into()
        })
        .collect()
}

fn exit_node_menu(
    status: &TailscaleStatus,
    prefs: &TailscalePrefs,
) -> Vec<ksni::MenuItem<TailscaleTray>> {
    trace!("Building exit node menu");
    let advertising_exit_node = prefs
        .advertise_routes
        .iter()
        .flatten()
        .any(|r| r.ends_with("/0"));

    debug!(
        "Currently advertising as exit node: {}",
        advertising_exit_node
    );
    let online_exit_nodes = status.online_exit_nodes();
    debug!("Available exit nodes: {}", online_exit_nodes.len());

    let mut res: Vec<ksni::MenuItem<TailscaleTray>> = vec![];
    for node in online_exit_nodes {
        let prefs_clone = prefs.clone();
        let eno = if node.exit_node {
            ExitNodeOption::None
        } else {
            ExitNodeOption::UseNode(node.host_name.clone())
        };
        res.push(
            CheckmarkItem {
                label: node.host_name.clone(),
                checked: node.exit_node,
                activate: Box::new(move |this: &mut TailscaleTray| {
                    info!("User changing exit node configuration");
                    if let Err(err) = this.exec.up_reconf(&eno, &prefs_clone) {
                        error!("Failed to reconfigure exit node: {:#}", err);
                        notify_of_failure(&err);
                    } else {
                        info!("Successfully reconfigured exit node");
                    }
                }),
                ..Default::default()
            }
            .into(),
        );
    }

    if !res.is_empty() {
        res.push(ksni::MenuItem::Separator)
    }
    let prefs_clone = Cell::new(prefs.clone());
    let cur_exit_node = status.peer.as_ref().and_then(|peers| {
        peers
            .values()
            .find(|&node| node.id == prefs.exit_node_id)
            .map(|node| node.host_name.clone())
    });

    if !prefs.exit_node_id.is_empty() {
        res.push(
            CheckmarkItem {
                label: "Allow LAN Access".into(),
                checked: prefs.exit_node_allow_lan_access,
                activate: Box::new(move |this: &mut TailscaleTray| {
                    info!("User changing exit node LAN access configuration");
                    let mut prefs = prefs_clone.take();
                    let new_value = !prefs.exit_node_allow_lan_access;
                    prefs.exit_node_allow_lan_access = new_value;

                    let eno = match cur_exit_node {
                        Some(ref id) => ExitNodeOption::UseNode(id.clone()),
                        None => ExitNodeOption::None,
                    };
                    if let Err(err) = this.exec.up_reconf(&eno, &prefs) {
                        error!("Failed to reconfigure exit node LAN access: {:#}", err);
                        notify_of_failure(&err);
                    } else {
                        info!("Successfully reconfigured exit node LAN access");
                    }
                }),
                ..Default::default()
            }
            .into(),
        );
    }
    let prefs_clone = prefs.clone();
    res.push(
        CheckmarkItem {
            label: "Run exit node".into(),
            checked: advertising_exit_node,
            activate: Box::new(move |this: &mut TailscaleTray| {
                let eno = if advertising_exit_node {
                    info!("User disabling exit node advertisement");
                    ExitNodeOption::None
                } else {
                    info!("User enabling exit node advertisement");
                    ExitNodeOption::Advertise
                };
                if let Err(err) = this.exec.up_reconf(&eno, &prefs_clone) {
                    error!("Failed to reconfigure exit node advertisement: {:#}", err);
                    notify_of_failure(&err);
                } else {
                    info!("Successfully reconfigured exit node advertisement");
                }
            }),
            ..Default::default()
        }
        .into(),
    );

    res
}

fn notify_of_failure(err: &anyhow::Error) {
    let err_string = err.to_string();
    error!("Tailscale operation failed: {}", err_string);
    thread::spawn(move || {
        match Notification::new()
            .summary("Tailscale error")
            .body(&err_string)
            .icon("network-error")
            .show()
        {
            Ok(_) => debug!("Displayed error notification"),
            Err(e) => error!("Failed to display error notification: {}", e),
        }
    });
}

fn enable_namespace_isolation() {
    let systray_path = std::env::current_exe().expect("Failed to get current executable path");

    let output = std::process::Command::new("pkexec")
        .arg(systray_path)
        .arg("-v")
        .arg(log::max_level().to_int().to_string())
        .arg("systemd")
        .arg("ns-install")
        .output();

    match output {
        Ok(out) if out.status.success() => {
            info!("Successfully enabled namespace isolation");
            let _ = Notification::new()
                .summary("Namespace Isolation Enabled")
                .body("Tailscaled is now running in an isolated namespace")
                .show();
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Failed to enable namespace isolation: {}", stderr);
            let _ = Notification::new()
                .summary("Failed to Enable Namespace Isolation")
                .body(&stderr)
                .show();
        }
        Err(e) => {
            error!("Failed to run pkexec: {:#}", e);
            let _ = Notification::new()
                .summary("Failed to Enable Namespace Isolation")
                .body(&format!("Error: {}", e))
                .show();
        }
    }
}

fn disable_namespace_isolation() {
    let systray_path = std::env::current_exe().expect("Failed to get current executable path");

    let output = std::process::Command::new("pkexec")
        .arg(systray_path)
        .arg("-v")
        .arg(log::max_level().to_int().to_string())
        .arg("systemd")
        .arg("ns-uninstall")
        .output();

    match output {
        Ok(out) if out.status.success() => {
            info!("Successfully disabled namespace isolation");
            let _ = Notification::new()
                .summary("Namespace Isolation Disabled")
                .body("Tailscaled is now running without namespace isolation")
                .show();
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!("Failed to disable namespace isolation: {}", stderr);
            let _ = Notification::new()
                .summary("Failed to Disable Namespace Isolation")
                .body(&stderr)
                .show();
        }
        Err(e) => {
            error!("Failed to run pkexec: {:#}", e);
            let _ = Notification::new()
                .summary("Failed to Disable Namespace Isolation")
                .body(&format!("Error: {}", e))
                .show();
        }
    }
}

fn namespace_menu() -> Vec<ksni::MenuItem<TailscaleTray>> {
    trace!("Building namespace menu");

    let mut menu = vec![StandardItem {
        label: "Run...".into(),
        activate: Box::new(|_| {
            info!("User requested to run command in namespace");
            thread::spawn(run_command_dialog);
        }),
        ..Default::default()
    }
    .into()];

    // Add command history
    let history = command_history::get_recent_commands();
    if !history.is_empty() {
        menu.push(ksni::MenuItem::Separator);

        for cmd in history {
            let cmd_clone = cmd.clone();
            menu.push(
                StandardItem {
                    label: cmd.clone(),
                    activate: Box::new(move |_| {
                        info!("User selected command from history: {}", cmd_clone);
                        let cmd_to_run = cmd_clone.clone();
                        thread::spawn(move || run_command_in_namespace(&cmd_to_run));
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
    }

    // Add separator and disable option
    menu.push(ksni::MenuItem::Separator);
    menu.push(
        StandardItem {
            label: "Disable Namespace Isolation...".into(),
            activate: Box::new(|_| {
                info!("User requested to disable namespace isolation");
                thread::spawn(disable_namespace_isolation);
            }),
            ..Default::default()
        }
        .into(),
    );

    menu
}

fn run_command_dialog() {
    info!("Opening command input dialog");

    // Use zenity to get user input
    let output = std::process::Command::new("zenity")
        .arg("--entry")
        .arg("--title=Run in Namespace")
        .arg("--text=Enter command to run in the isolated namespace:")
        .arg("--width=500")
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let command = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !command.is_empty() {
                info!("User entered command: {}", command);
                run_command_in_namespace(&command);
            } else {
                debug!("User entered empty command");
            }
        }
        Ok(out) if out.status.code() == Some(1) => {
            // User cancelled (exit code 1)
            debug!("User cancelled command input dialog");
        }
        Ok(out) => {
            warn!("zenity exited with code: {:?}", out.status.code());
        }
        Err(e) => {
            error!("Failed to run zenity: {:#}", e);
            let _ = Notification::new()
                .summary("Failed to open dialog")
                .body(&format!("Error: {}. Is zenity installed?", e))
                .show();
        }
    }
}

fn run_command_in_namespace(command: &str) {
    info!("Running command in namespace: {}", command);

    // Add to history
    command_history::add_to_history(command);

    // Get current executable path for tailscale-systray
    let systray_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to get current executable path: {}", e);
            let _ = Notification::new()
                .summary("Command Failed")
                .body(&format!("Failed to get executable path: {}", e))
                .show();
            return;
        }
    };

    // Parse the command into shell form
    // We'll use sh -c to execute the command
    let output = std::process::Command::new(&systray_path)
        .arg("ns-enter")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(command)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            info!("Successfully launched command in namespace");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!(
                "Command failed to launch in namespace with exit code {:?}: {}",
                out.status.code(),
                stderr
            );
            let _ = Notification::new()
                .summary("Command Failed")
                .body(&format!("Exit code: {:?}\n{}", out.status.code(), stderr))
                .show();
        }
        Err(e) => {
            error!("Failed to execute command: {:#}", e);
            let _ = Notification::new()
                .summary("Command Failed")
                .body(&format!("Error: {}", e))
                .show();
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Verbosity level (0-5, where 0=error, 1=warn, 2=info, 3=debug, 4=trace, 5=trace+)
    #[arg(short, long, default_value_t = 2u8)]
    verbosity: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the application normally
    Run {
        /// Tailscale executable
        #[arg(long, default_value = "tailscale")]
        tailscale_bin: PathBuf,

        /// Path to tailscaled socket
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Extra arguments to pass "tailscale up"
        #[arg(long)]
        up_arg: Vec<OsString>,

        /// Refresh period in seconds
        #[arg(long, default_value_t = 5u64)]
        refresh_period: u64,
    },

    /// Install icons and desktop file
    Install,

    /// Prepare segregated networking
    NsPrepare,

    /// Launch namespace fd supplier
    NsHelper {
        /// The file descriptor for the unix socket
        #[arg(long)]
        abstract_path: PathBuf,
    },

    /// Enter the namespaces for the segregated network and execute
    NsEnter {
        /// Additional environment variables to set in key=value format
        #[arg(long, num_args = 0.., value_parser = parse_key_val::<OsString, OsString>, value_name="<env name>=<env value>")]
        env: Vec<(OsString, OsString)>,

        /// File descriptors to remap (read-write), e.g. `0=/proc/self/fd/0`
        #[arg(long, num_args = 0.., value_parser = parse_key_val::<i32, PathBuf>, value_name="<fd>=<path>")]
        fd: Vec<(i32, PathBuf)>,

        /// File descriptors to remap (read-only)
        #[arg(long, num_args = 0.., value_parser = parse_key_val::<i32, PathBuf>, value_name="<fd>=<path>")]
        fd_read: Vec<(i32, PathBuf)>,

        /// File descriptors to remap (append only)
        #[arg(long, num_args = 0.., value_parser = parse_key_val::<i32, PathBuf>, value_name="<fd>=<path>")]
        fd_write: Vec<(i32, PathBuf)>,

        /// The command to execute and its arguments
        #[arg(required = true, num_args = 1.., last = true)]
        command: Vec<OsString>,
    },

    /// Systemd integration commands
    Systemd {
        #[command(subcommand)]
        subcmd: SystemdCommand,
    },
}

#[derive(Subcommand, Debug)]
enum SystemdCommand {
    /// Install systemd drop-in to run tailscaled in isolated namespaces
    NsInstall {
        /// Path to tailscale-systray binary (defaults to current executable)
        #[arg(long)]
        systray_path: Option<PathBuf>,
    },

    /// Uninstall systemd drop-in (restore normal tailscaled operation)
    NsUninstall,
}

fn parse_key_val<K, V>(s: &str) -> Result<(K, V), String>
where
    K: FromStr,
    V: FromStr,
{
    let pos = s.find('=').ok_or("must be in key=value format")?;
    let (k, v) = s.split_at(pos);
    let key = K::from_str(k).map_err(|_| format!("error converting key: {}", k))?;
    let value = V::from_str(&v[1..]).map_err(|_| format!("error converting value: {}", v))?;
    Ok((key, value))
}

fn open_file_descriptors(
    fd: &[(i32, PathBuf)],
    fd_read: &[(i32, PathBuf)],
    fd_write: &[(i32, PathBuf)],
) -> Result<Vec<(i32, std::fs::File)>, io::Error> {
    use std::fs::OpenOptions;

    let mut opened_fds = Vec::new();

    // Open read-write files (fd) - create if doesn't exist, don't truncate
    for (target_fd, path) in fd {
        let file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(path)?;
        opened_fds.push((*target_fd, file));
    }

    // Open read-only files (fd_read) - don't create
    for (target_fd, path) in fd_read {
        let file = OpenOptions::new().read(true).open(path)?;
        opened_fds.push((*target_fd, file));
    }

    // Open write-only files (fd_write) - create if doesn't exist, don't truncate
    for (target_fd, path) in fd_write {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        opened_fds.push((*target_fd, file));
    }

    Ok(opened_fds)
}
impl Default for Command {
    fn default() -> Self {
        Command::Run {
            tailscale_bin: PathBuf::from("tailscale"),
            socket: None,
            up_arg: vec![],
            refresh_period: 5,
        }
    }
}

fn setup_logger(verbosity: u8) {
    let level = LevelFilter::from_int(verbosity);

    let mut builder = env_logger::Builder::new();

    if !io::stdout().is_terminal() {
        builder.format(move |buf, record| {
            writeln!(buf, "[{}][{}] {}", record.level(), getpid(), record.args())
        });
    }

    builder.filter_level(level).init();
}

pub trait LevelFilterExt {
    fn from_int(i: u8) -> LevelFilter;
    fn to_int(&self) -> u8;
}
impl LevelFilterExt for LevelFilter {
    fn from_int(i: u8) -> LevelFilter {
        match i {
            0 => LevelFilter::Error,
            1 => LevelFilter::Warn,
            2 => LevelFilter::Info,
            3 => LevelFilter::Debug,
            4 | 5 => LevelFilter::Trace,
            _ => LevelFilter::Info,
        }
    }

    fn to_int(&self) -> u8 {
        match self {
            LevelFilter::Off => 0,
            LevelFilter::Error => 0,
            LevelFilter::Warn => 1,
            LevelFilter::Info => 2,
            LevelFilter::Debug => 3,
            LevelFilter::Trace => 4,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    setup_logger(args.verbosity);
    info!(
        "Starting Tailscale systray with verbosity level {}",
        args.verbosity
    );

    match &args.command {
        Some(ref cmd @ Command::Run { .. }) => {
            run_command(cmd).await;
        }
        None => {
            info!("No command provided, running in default mode");
            run_command(&Command::default()).await;
        }
        Some(Command::Install) => match installation::local_install() {
            Ok(_) => {
                info!("Local installation completed successfully");
                return;
            }
            Err(e) => {
                error!("Local installation failed: {}", e);
                std::process::exit(1);
            }
        },
        Some(Command::NsPrepare) => {
            info!("Preparing segregated networking");
            if let Err(e) = namespaces::setup_interfaces().await {
                error!("Failed to prepare segregated networking: {:#}", e);
                std::process::exit(1);
            }
            info!("Segregated networking prepared successfully");
        }
        Some(Command::NsHelper { abstract_path }) => {
            info!("Helper: starting namespace helper");
            match ns_launcher::handle_helper_process(abstract_path).await {
                Ok(_) => info!("Helper: namespace helper finished successfully"),
                Err(e) => {
                    error!("Helper: namespace helper errored: {:#}", e);
                    std::process::exit(1);
                }
            };
        }
        Some(Command::NsEnter {
            env,
            fd,
            fd_read,
            fd_write,
            command,
        }) => loop {
            info!(
                "Sending command for executing in the helper process: {:?}",
                command
            );
            let socket_path = Path::new("/tailscale-systray-ns.sock");
            match NamespaceLauncher::new(socket_path).await {
                Ok(ns_launcher) => {
                    info!("Connected to namespace helper process");

                    let executable = PathBuf::from(&command[0]);
                    let args = command.clone();

                    // Open the specified file descriptors
                    let fds = match open_file_descriptors(fd, fd_read, fd_write) {
                        Ok(fds) => fds,
                        Err(e) => {
                            error!("Failed to open file descriptors: {:#}", e);
                            std::process::exit(1);
                        }
                    };

                    let res = ns_launcher
                        .launch_in_ns(executable, args, env.clone(), fds)
                        .await;
                    match res {
                        Err(e) => {
                            error!("Failed launching {:?} in namespaces: {:#}", command[0], e);
                            std::process::exit(1);
                        }
                        Ok(ns_launcher::LaunchResult::Success) => {
                            info!("Successfully launched {:?} in namespaces", command[0]);
                            break;
                        }
                        Ok(ns_launcher::LaunchResult::Stale) => {
                            info!(
                                "Namespace state changed, retrying launch of {:?}",
                                command[0]
                            );
                            // Retry launching the command after a small wait
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!("Namespace helper errored: {:#}", e);
                    std::process::exit(1);
                }
            }
        },
        Some(Command::Systemd { subcmd }) => match subcmd {
            SystemdCommand::NsInstall { systray_path } => {
                info!("Installing systemd drop-in for namespace isolation");

                // Use provided path or get current executable
                let binary_path = match systray_path {
                    Some(path) => path.clone(),
                    None => std::env::current_exe()
                        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/tailscale-systray")),
                };

                info!(
                    "Using tailscale-systray binary at: {}",
                    binary_path.display()
                );

                match systemd::install_dropin(&binary_path).await {
                    Ok(_) => {
                        info!("Successfully installed systemd drop-in and restarted tailscaled");
                    }
                    Err(e) => {
                        error!("Failed to install systemd drop-in: {:#}", e);
                        std::process::exit(1);
                    }
                }
            }
            SystemdCommand::NsUninstall => {
                info!("Uninstalling systemd drop-in");

                match systemd::uninstall_dropin().await {
                    Ok(_) => {
                        info!("Successfully uninstalled systemd drop-in and restarted tailscaled");
                    }
                    Err(e) => {
                        error!("Failed to uninstall systemd drop-in: {:#}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}

async fn run_command(cmd: &Command) {
    let Command::Run {
        ref tailscale_bin,
        ref socket,
        ref up_arg,
        refresh_period,
    } = cmd
    else {
        panic!("run_command should only be called with Command::Run");
    };

    debug!("Using Tailscale binary: {:?}", tailscale_bin);
    if let Some(socket) = socket {
        debug!("Using Tailscale socket: {:?}", socket);
    }
    if !up_arg.is_empty() {
        debug!("Additional 'up' arguments: {:?}", up_arg);
    }

    // Check if tailscaled.service exists and if running in namespace
    let has_systemd_service = systemd::tailscaled_service_exists().await;
    trace!("tailscaled.service detected: {has_systemd_service}");

    let tray = TailscaleTray::new(tailscale_bin, socket, up_arg, has_systemd_service).await;
    info!("Initializing system tray");
    let handle = match tray.spawn().await {
        Ok(h) => {
            info!("System tray initialized successfully");
            h
        }
        Err(e) => {
            error!("Failed to initialize system tray: {:#}", e);
            panic!("Failed to initialize system tray: {:#}", e);
        }
    };

    info!(
        "Starting refresh loop with period of {} seconds",
        refresh_period
    );
    loop {
        trace!("Waiting for next refresh cycle");
        tokio::time::sleep(std::time::Duration::from_secs(*refresh_period)).await;

        trace!("Updating tray status and namespace state");
        let in_namespace = has_systemd_service && TailscaleTray::fetch_namespace_status().await;
        if (handle
            .update(|tray: &mut TailscaleTray| {
                tray.refetch_status();
                tray.set_namespace_status(in_namespace);
            })
            .await)
            .is_none()
        {
            error!("The tray service has shutdown");
            break;
        } else {
            trace!("Tray update completed");
        }
    }
}
