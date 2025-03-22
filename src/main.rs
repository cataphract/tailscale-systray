use std::{ffi::OsString, io, path::PathBuf, thread};

use arboard::Clipboard;
use clap::Parser;
use ksni::{
    menu::{CheckmarkItem, StandardItem},
    Tray, TrayMethods,
};
use log::{debug, error, info, trace, warn, LevelFilter};
use notify_rust::Notification;
use std::io::{IsTerminal, Write};
use tailscale::{ExitNodeOption, TailscaleExec, TailscalePrefs, TailscaleStatus};

mod tailscale;

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
}
impl TailscaleTray {
    fn new(args: &Args) -> Self {
        let exec = TailscaleExec::new(
            args.tailscale_bin.clone(),
            args.socket.as_ref(),
            args.up_arg.clone(),
        );
        let status = TailscaleTray::fetch_status(&exec);
        let prefs = match status {
            ServiceState::Running(_) => TailscaleTray::fetch_prefs(&exec),
            _ => None,
        };

        Self {
            exec,
            status,
            prefs,
            clipboard: Clipboard::new().unwrap(),
        }
    }

    fn fetch_status(exec: &TailscaleExec) -> ServiceState {
        trace!("Fetching Tailscale status");
        exec.status()
            .map(|s| ServiceState::Running(Box::new(s)))
            .unwrap_or_else(|e| {
                warn!("Failed to fetch Tailscale status: {}", e);
                ServiceState::Down
            })
    }

    fn fetch_prefs(exec: &TailscaleExec) -> Option<Box<TailscalePrefs>> {
        trace!("Fetching Tailscale preferences");
        match exec.prefs() {
            Ok(prefs) => Some(Box::new(prefs)),
            Err(e) => {
                warn!("Failed to fetch Tailscale preferences: {}", e);
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

    fn icon_theme_path(&self) -> String {
        "/home/glopes/repos/tailscale-systray/icons".into()
    }

    fn icon_name(&self) -> String {
        match &self.status {
            ServiceState::Down => "tailscale-down",
            ServiceState::Running(status) => {
                if status.self_node.online {
                    if status.exit_node_status.as_ref().is_some_and(|x| x.online) {
                        "tailscale-exit-node"
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
                                        error!("Failed to disable Tailscale: {}", err);
                                        notify_of_failure(&err);
                                    } else {
                                        info!("Successfully disabled Tailscale");
                                    }
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
                                        error!("Failed to enable Tailscale: {}", err);
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
                        error!("Failed to reconfigure exit node: {}", err);
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

    let prefs_clone = prefs.clone();
    if !res.is_empty() {
        res.push(ksni::MenuItem::Separator)
    }
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
                    error!("Failed to reconfigure exit node advertisement: {}", err);
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

#[derive(Parser, Debug)]
struct Args {
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
    #[arg(long, default_value = "5")]
    refresh_period: u64,

    /// Verbosity level (0-5, where 0=error, 1=warn, 2=info, 3=debug, 4=trace, 5=trace+)
    #[arg(short, long, default_value = "2")]
    verbosity: u8,
}

fn setup_logger(verbosity: u8) {
    let level = match verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        4 | 5 => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };

    let mut builder = env_logger::Builder::new();

    if !io::stdout().is_terminal() {
        builder.format(move |buf, record| writeln!(buf, "[{}] {}", record.level(), record.args()));
    }

    builder.filter_level(level).init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    setup_logger(args.verbosity);

    info!(
        "Starting Tailscale systray with verbosity level {}",
        args.verbosity
    );
    debug!("Using Tailscale binary: {:?}", args.tailscale_bin);
    if let Some(socket) = &args.socket {
        debug!("Using Tailscale socket: {:?}", socket);
    }
    if !args.up_arg.is_empty() {
        debug!("Additional 'up' arguments: {:?}", args.up_arg);
    }

    let tray = TailscaleTray::new(&args);
    info!("Initializing system tray");
    let handle = match tray.spawn().await {
        Ok(h) => {
            info!("System tray initialized successfully");
            h
        }
        Err(e) => {
            error!("Failed to initialize system tray: {}", e);
            panic!("Failed to initialize system tray: {}", e);
        }
    };

    info!(
        "Starting refresh loop with period of {} seconds",
        args.refresh_period
    );
    loop {
        trace!("Waiting for next refresh cycle");
        tokio::time::sleep(std::time::Duration::from_secs(args.refresh_period)).await;

        trace!("Updating tray status");
        if (handle
            .update(|tray: &mut TailscaleTray| tray.refetch_status())
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
