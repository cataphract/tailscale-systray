use anyhow::{bail, Context};
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::BufRead,
    path::PathBuf,
    process::{self, Command, Stdio},
};
use users::get_current_username;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailscaleStatus {
    pub version: String,
    #[serde(rename = "TUN")]
    pub tun: bool,
    pub backend_state: String,
    pub have_node_key: Option<bool>,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Self")]
    pub self_node: Node,
    pub exit_node_status: Option<ExitNodeStatus>,
    pub health: Vec<String>,
    #[serde(rename = "MagicDNSSuffix")]
    pub magic_dns_suffix: String,
    pub current_tailnet: Option<CurrentTailnet>,
    pub cert_domains: Option<Vec<String>>,
    pub peer: Option<HashMap<String, Node>>,
    pub user: Option<HashMap<String, User>>,
    pub client_version: Option<serde_json::Value>,
}

impl TailscaleStatus {
    fn filter_peers(&self, f: impl Fn(&Node) -> bool) -> Vec<&Node> {
        let mut col: Vec<&Node> = self
            .peer
            .as_ref()
            .into_iter()
            .flat_map(|peers| peers.values().filter(|p| f(p)))
            .collect();
        col.sort_by_key(|p| &p.host_name);
        col
    }

    pub fn online_peers(&self) -> Vec<&Node> {
        self.filter_peers(|p| p.online)
    }

    pub fn online_exit_nodes(&self) -> Vec<&Node> {
        self.filter_peers(|p| (p.online && p.exit_node_option) || p.exit_node)
    }
}

// shared type for both Self and Peer fields
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: String,
    pub public_key: String,
    pub host_name: String,
    #[serde(rename = "DNSName")]
    pub dns_name: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "UserID")]
    pub user_id: u64,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<String>>,
    // Some fields may be null or missing in some nodes
    pub addrs: Option<Vec<String>>,
    pub cur_addr: Option<String>,
    pub relay: String,
    pub peer_relay: Option<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub created: Option<String>,
    pub last_write: Option<String>,
    pub last_seen: Option<String>,
    pub last_handshake: Option<String>,
    pub online: bool,
    pub exit_node: bool,
    pub exit_node_option: bool,
    pub active: Option<bool>,
    #[serde(rename = "PeerAPIURL")]
    pub peer_api_url: Option<Vec<String>>,
    pub taildrop_target: Option<u32>,
    pub no_file_sharing_reason: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub cap_map: Option<HashMap<String, Option<serde_json::Value>>>,
    pub primary_routes: Option<Vec<String>>,
    pub in_network_map: Option<bool>,
    pub in_magic_sock: Option<bool>,
    pub in_engine: Option<bool>,
    pub key_expiry: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CurrentTailnet {
    pub name: String,
    #[serde(rename = "MagicDNSSuffix")]
    pub magic_dns_suffix: String,
    #[serde(rename = "MagicDNSEnabled")]
    pub magic_dns_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User {
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default)]
    pub profile_pic_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExitNodeStatus {
    #[serde(rename = "ID")]
    pub id: String,
    pub online: bool,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TailscalePrefs {
    #[serde(rename = "ControlURL")]
    pub control_url: String,
    pub route_all: bool,
    #[serde(rename = "ExitNodeID")]
    pub exit_node_id: String,
    #[serde(rename = "ExitNodeIP")]
    pub exit_node_ip: String,
    pub internal_exit_node_prior: String,
    #[serde(rename = "ExitNodeAllowLANAccess")]
    pub exit_node_allow_lan_access: bool,
    #[serde(rename = "CorpDNS")]
    pub corp_dns: bool,
    #[serde(rename = "RunSSH")]
    pub run_ssh: bool,
    pub run_web_client: bool,
    pub want_running: bool,
    pub logged_out: bool,
    pub shields_up: bool,
    pub advertise_tags: Option<Vec<String>>,
    pub hostname: String,
    #[serde(rename = "NotepadURLs")]
    pub notepad_urls: bool,
    pub advertise_routes: Option<Vec<String>>,
    pub advertise_services: Option<Vec<String>>,
    #[serde(rename = "NoSNAT")]
    pub no_snat: bool,
    pub no_stateful_filtering: bool,
    pub netfilter_mode: i32,
    pub auto_update: AutoUpdate,
    pub app_connector: AppConnector,
    pub posture_checking: bool,
    pub netfilter_kind: String,
    pub drive_shares: Option<Vec<String>>,
    pub allow_single_hosts: bool,
    pub config: Option<Config>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct AutoUpdate {
    pub check: bool,
    pub apply: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "PascalCase")]
pub struct AppConnector {
    pub advertise: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub private_node_key: String,
    pub old_private_node_key: String,
    pub user_profile: UserProfile,
    pub network_lock_key: String,
    #[serde(rename = "NodeID")]
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: u64,
    pub login_name: String,
    pub display_name: String,
    #[serde(rename = "ProfilePicURL", default)]
    pub profile_pic_url: String,
}

pub struct TailscaleExec {
    cmd: PathBuf,
    flags: Vec<OsString>,
    up_flags: Vec<OsString>,
}

pub enum ExitNodeOption {
    None,
    UseNode(String),
    Advertise,
}

impl TailscaleExec {
    pub fn new(cmd: PathBuf, socket: Option<&PathBuf>, up_flags: Vec<OsString>) -> Self {
        Self {
            cmd,
            flags: socket
                .map(|socket| vec!["--socket".into(), socket.into()])
                .unwrap_or_default(),
            up_flags,
        }
    }

    fn command<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut cmd = Command::new(&self.cmd);
        cmd.args(&self.flags).args(args);
        cmd
    }

    fn json_command<T, S>(&self, args: &[S]) -> anyhow::Result<T>
    where
        for<'a> T: serde::de::Deserialize<'a>,
        S: AsRef<OsStr>,
    {
        let mut command = self.command(args);
        let output = command
            .output()
            .with_context(|| format!("Failed executing command {:?}", command))?;

        let res: T = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "For command {:?}, failed parsing output {}, stderr: {}",
                command,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        Ok(res)
    }

    pub fn status(&self) -> anyhow::Result<TailscaleStatus> {
        self.json_command(&["status", "--json"])
    }

    pub fn prefs(&self) -> anyhow::Result<TailscalePrefs> {
        self.json_command(&["debug", "prefs"])
    }

    fn retry_with_sudo<S: AsRef<OsStr>>(&self, args: &[S]) -> anyhow::Result<process::Output> {
        let mut command = self.command(args);
        let res = command.output()?;

        if !res.status.success() && String::from_utf8_lossy(&res.stderr).contains("Access denied") {
            let mut command = Command::new("pkexec");
            command.arg(&self.cmd);
            command.args(&self.flags).args(args);
            Ok(command.output()?)
        } else {
            Ok(res)
        }
    }

    pub fn up(&self) -> anyhow::Result<()> {
        let res = self
            .retry_with_sudo(&["up"])
            .context("Could not execute tailscale up")?;

        if res.status.success() {
            Ok(())
        } else {
            bail!(
                "tailscale up failed: {}",
                String::from_utf8_lossy(&res.stderr)
            );
        }
    }

    fn operator_arg() -> Option<OsString> {
        get_current_username().map(|username| {
            let mut operator_arg = OsString::from("--operator=");
            operator_arg.push(username);
            operator_arg
        })
    }

    pub fn up_reconf(
        &self,
        exit_node_opt: &ExitNodeOption,
        prefs: &TailscalePrefs,
    ) -> anyhow::Result<()> {
        let mut args: Vec<OsString> = vec!["up".into(), "--reset".into()];
        if let Some(operator_arg) = Self::operator_arg() {
            args.push(operator_arg);
        }
        if prefs.route_all {
            args.push("--accept-routes".into());
        }
        if prefs.exit_node_allow_lan_access {
            args.push("--exit-node-allow-lan-access".into());
        }
        match exit_node_opt {
            ExitNodeOption::None => {}
            ExitNodeOption::UseNode(node) => {
                args.push("--exit-node".into());
                args.push(node.into());
            }
            ExitNodeOption::Advertise => {
                args.push("--advertise-exit-node".into());
            }
        }
        args.extend(self.up_flags.iter().cloned());

        let res = self
            .retry_with_sudo(&args)
            .context("Could not execute tailscale up")?;

        if res.status.success() {
            Ok(())
        } else {
            bail!(
                "tailscale up failed: {}",
                String::from_utf8_lossy(&res.stderr)
            );
        }
    }

    pub fn down(&self) -> anyhow::Result<()> {
        let res = self
            .retry_with_sudo(&["down"])
            .context("Could not execute tailscale down")?;

        if res.status.success() {
            Ok(())
        } else {
            bail!(
                "tailscale down failed: {}",
                String::from_utf8_lossy(&res.stderr)
            );
        }
    }

    pub fn login(&self) {
        let mut cmd = Command::new(&self.cmd);
        cmd.args(&self.flags).args(["login"]);

        let mut sudo_cmd = Command::new("pkexec");
        sudo_cmd.arg(&self.cmd).args(&self.flags).arg("login");
        if let Some(operator_arg) = Self::operator_arg() {
            sudo_cmd.arg(operator_arg);
        }

        std::thread::spawn(move || {
            let mut tried_sudo = false;
            let mut cmd = &mut cmd;

            loop {
                debug!("About to spawn {:?}", cmd);
                cmd.stderr(Stdio::piped());

                let mut child = match cmd.spawn() {
                    Ok(child) => child,
                    Err(e) => {
                        warn!("Failed to start tailscale login: {:#}", e);
                        return;
                    }
                };

                let stderr = child.stderr.take().unwrap();
                let mut reader = std::io::BufReader::new(stderr);

                let mut line = String::new();

                // read first line of stderr
                let read = reader.read_line(&mut line);
                trace!("tailscale login output: {}", line);
                if read.is_ok() && !tried_sudo && line.contains("Access denied") {
                    info!("Access denied on tailscale login, trying with sudo");
                    child.kill().ok();
                    tried_sudo = true;
                    cmd = &mut sudo_cmd;
                    continue;
                }

                loop {
                    line.clear();
                    let read = reader.read_line(&mut line);
                    trace!("tailscale login output: {}", line);

                    if read.is_ok() && line.contains("https://") {
                        let https_pos = line.find("https://").unwrap();
                        let url_start = &line[https_pos..];
                        let end_pos = url_start
                            .find(|c: char| c.is_whitespace())
                            .unwrap_or(url_start.len());
                        let url = &url_start[..end_pos];

                        let res = Command::new("xdg-open").arg(url).output();
                        if let Err(e) = res {
                            error!("Failed to open login url: {:#}", e);
                        } else {
                            info!("Opened login url in browser: {}", url);
                            debug!("Waiting for tailscale login to exit");
                            let _ = child.wait();
                            debug!("Wait for tailscale login to exit finished");
                        }
                        return;
                    }
                    if let Ok(0) = read {
                        error!("tailscale login output finished without login url");
                        child.kill().ok();
                        return;
                    }
                }
            }
        });
    }
}

#[test]
fn print_running() {
    let json_str = include_str!("../json/status_running.json");

    let status: TailscaleStatus = serde_json::from_str(json_str).unwrap();

    println!("Version: {}", status.version);
    println!("Self HostName: {}", status.self_node.host_name);
    println!("Number of peers: {}", status.peer.as_ref().unwrap().len());

    for (public_key, peer) in status.peer.as_ref().unwrap() {
        println!(
            "Peer: {} ({}) - Online: {}",
            peer.host_name, public_key, peer.online
        );
    }
}

#[test]
fn print_starting() {
    let json_str = include_str!("../json/status_starting.json");
    let status = serde_json::from_str::<TailscaleStatus>(json_str).unwrap();
    println!("status: {:?}", status);
}

#[test]
fn print_needs_login() {
    let json_str = include_str!("../json/status_needs_login.json");
    let status = serde_json::from_str::<TailscaleStatus>(json_str).unwrap();
    println!("status: {:?}", status);

    let json_str = include_str!("../json/prefs_needs_login.json");
    let prefs = serde_json::from_str::<TailscalePrefs>(json_str).unwrap();
    println!("prefs: {:?}", prefs);
}

#[test]
fn print_live_status() {
    let tailscale = TailscaleExec::new("tailscale".into(), None, vec![]);
    let status = tailscale.status().unwrap();

    println!("Version: {}", status.version);
    println!("Self HostName: {}", status.self_node.host_name);
    let num_peers = status
        .peer
        .as_ref()
        .map(|peers| peers.len())
        .unwrap_or_default();
    println!("Number of peers: {}", num_peers);

    if let Some(ref peers) = status.peer {
        for (public_key, peer) in peers {
            println!(
                "Peer: {} ({}) - Online: {}",
                peer.host_name, public_key, peer.online
            );
        }
    }
}
