use std::{ffi::OsString, path::PathBuf, thread};

use arboard::Clipboard;
use clap::Parser;
use ksni::{
    menu::{CheckmarkItem, StandardItem},
    Tray, TrayMethods,
};
use notify_rust::Notification;
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
        exec.status()
            .map(|s| ServiceState::Running(Box::new(s)))
            .unwrap_or(ServiceState::Down)
    }

    fn fetch_prefs(exec: &TailscaleExec) -> Option<Box<TailscalePrefs>> {
        exec.prefs().ok().map(Box::new)
    }

    fn refetch_status(&mut self) {
        // println!("Refetching status");
        self.status = Self::fetch_status(&self.exec);
        self.prefs = match &self.status {
            ServiceState::Running(_) => Self::fetch_prefs(&self.exec),
            _ => None,
        };
        println!("Refetched status: {:?}", self.status);
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
                    let first_ip = tstatus.tailscale_ips.first().map(|s| s.to_owned());
                    let mut res: Vec<ksni::MenuItem<TailscaleTray>> = vec![StandardItem {
                        label: format!(
                            "{}: {}",
                            tstatus.self_node.host_name, tstatus.backend_state
                        ),
                        activate: Box::new(move |this: &mut Self| {
                            if let Some(ip) = &first_ip {
                                this.clipboard.set_text(ip).unwrap();
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
                                    if let Err(err) = this.exec.down() {
                                        notify_of_failure(&err);
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
                                    if let Err(err) = this.exec.up() {
                                        notify_of_failure(&err);
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
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );
        res
    }
}

fn online_peers(status: &TailscaleStatus) -> Vec<ksni::MenuItem<TailscaleTray>> {
    status
        .online_peers()
        .iter()
        .map(|p| {
            let first_ip = p.tailscale_ips.first().map(|ip| ip.to_string());
            StandardItem {
                label: p.host_name.clone(),
                activate: Box::new(move |this: &mut TailscaleTray| {
                    if let Some(ip) = &first_ip {
                        this.clipboard.set_text(ip).unwrap();
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
    let advertising_exit_node = prefs
        .advertise_routes
        .iter()
        .flatten()
        .any(|r| r.ends_with("/0"));

    let mut res: Vec<ksni::MenuItem<TailscaleTray>> = vec![];
    for node in status.online_exit_nodes() {
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
                    if let Err(err) = this.exec.up_reconf(&eno, &prefs_clone) {
                        notify_of_failure(&err);
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
                    ExitNodeOption::None
                } else {
                    ExitNodeOption::Advertise
                };
                if let Err(err) = this.exec.up_reconf(&eno, &prefs_clone) {
                    notify_of_failure(&err);
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
    thread::spawn(move || {
        let _ = Notification::new()
            .summary("Tailscale error")
            .body(&err_string)
            .icon("network-error")
            .show();
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

    /// Refresh period
    #[arg(long, default_value = "5")]
    refresh_period: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let tray = TailscaleTray::new(&args);
    let handle = tray.spawn().await.unwrap();

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(args.refresh_period)).await;
        let _ = handle
            .update(|tray: &mut TailscaleTray| tray.refetch_status())
            .await;
        println!("Await finished");
    }
}
