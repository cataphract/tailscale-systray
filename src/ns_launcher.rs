use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

use anyhow::Context;
use log::{debug, error, info, warn};
use nix::sched::{clone, setns, CloneFlags};
use nix::unistd::{close, execvpe, fork, ForkResult, Gid, Uid};
use nix::{
    cmsg_space,
    sys::{prctl, signal::Signal::SIGTERM},
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::{UnixListener, UnixStream};
use users::os::unix::UserExt;

use crate::namespaces;
use crate::systemd;
use crate::LevelFilterExt;

#[derive(Serialize, Deserialize, Debug)]
struct ExecRequest {
    executable: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    /// Target FD numbers - the same number of FDs will be sent over the socket
    /// Each received FD will be dup2'd to the corresponding target FD number
    fd_targets: Vec<RawFd>,
    cur_tailscaled_pid: Option<u32>,
}

fn create_abstract_unix_listener(socket_path: &PathBuf) -> anyhow::Result<UnixListener> {
    debug!(
        "Creating Unix socket in abstract namespace with path: {:?}",
        socket_path
    );

    let addr =
        std::os::unix::net::SocketAddr::from_abstract_name(socket_path.as_os_str().as_bytes())?;
    let std_listener =
        std::os::unix::net::UnixListener::bind_addr(&addr).context("bind call failed")?;

    std_listener
        .set_nonblocking(true)
        .context("Error setting stream to non-blocking mode")?;
    let listener = UnixListener::from_std(std_listener)?;

    Ok(listener)
}

async fn connect_abstract_unix<P>(
    socket_path: P,
    max_retries: usize,
    retry_delay: Duration,
) -> anyhow::Result<UnixStream>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    debug!(
        "Connecting to Unix socket in abstract namespace with path: {:?}",
        socket_path
    );

    let pref_socket_path = [&[0u8], socket_path.as_ref().as_os_str().as_bytes()].concat();
    let pref_socket_path = PathBuf::from(OsStr::from_bytes(&pref_socket_path));

    let stream = async {
        for attempt in 1..=max_retries {
            debug!(
                "Attempt {}/{} to connect to abstract socket: {:?}",
                attempt, max_retries, socket_path
            );

            match UnixStream::connect(&pref_socket_path).await {
                Err(e) => {
                    debug!("Connect call failed: {}", e);
                    if attempt == max_retries {
                        return Err(e).context("Failed to connect to abstract socket");
                    }
                    tokio::time::sleep(retry_delay).await;
                }
                Ok(stream) => {
                    debug!("Connected to abstract socket: {:?}", socket_path);
                    return Ok(stream);
                }
            }
        }
        anyhow::bail!("Connect retries exhausted");
    }
    .await?;

    Ok(stream)
}

pub async fn handle_helper_process(socket_path: &PathBuf) -> anyhow::Result<()> {
    prctl::set_pdeathsig(Some(SIGTERM)).context("Error setting pdeathsig")?;

    // Open the namespace files
    let net_ns_file = OpenOptions::new()
        .read(true)
        .open(namespaces::NET_NS_PATH)
        .context("Failed to open network namespace file")?;
    let net_ns_fd: OwnedFd = net_ns_file.into();

    let mnt_ns_file = OpenOptions::new()
        .read(true)
        .open(namespaces::MNT_NS_PATH)
        .context("Failed to open mount namespace file")?;
    let mnt_ns_fd: OwnedFd = mnt_ns_file.into();

    info!(
        "Helper: Opened namespace file descriptors: net={:?}, mnt={:?}",
        net_ns_fd, mnt_ns_fd
    );

    // Create, bind and listen to socket BEFORE entering namespaces
    // (abstract sockets are network-namespace-local)
    let listener = create_abstract_unix_listener(socket_path)
        .context("Failed to create abstract Unix socket")?;

    // Enter the namespaces
    info!("Helper: Entering network namespace");
    setns(&net_ns_fd, CloneFlags::CLONE_NEWNET).context("Failed to enter network namespace")?;

    info!("Helper: Entering mount namespace");
    setns(&mnt_ns_fd, CloneFlags::CLONE_NEWNS).context("Failed to enter mount namespace")?;

    // We no longer need the namespace file descriptors
    drop(net_ns_fd);
    drop(mnt_ns_fd);

    // Get the original user's UID and GID before dropping privileges
    let original_uid_u32 = std::env::var("PKEXEC_UID")
        .context("PKEXEC_UID is not set")?
        .parse::<u32>()
        .context("PKEXEC_UID is not a valid number")?;
    let original_uid = Uid::from_raw(original_uid_u32);

    let user =
        users::get_user_by_uid(original_uid.as_raw()).context("Failed to get user information")?;

    let original_gid = Gid::from_raw(user.primary_group_id());

    // Get all supplementary groups for the user
    let user_groups = users::get_user_groups(user.name().to_str().unwrap(), original_gid.as_raw())
        .context("Failed to get user groups")?;
    let supplementary_groups: Vec<Gid> = user_groups
        .iter()
        // for some reason 0 (root) is included in the supplementary groups, filter it out
        .filter(|g| g.gid() != 0)
        .map(|g| Gid::from_raw(g.gid()))
        .collect();
    debug!("User supplementary groups: {:?}", supplementary_groups);

    info!(
        "Helper: Dropping privileges to UID={}, GID={}, supplementary groups: {:?}",
        original_uid, original_gid, supplementary_groups
    );

    // set uid, gid and supplementary groups
    // Set supplementary groups first because they require root privileges
    nix::unistd::setgroups(&supplementary_groups).context("Failed to set supplementary groups")?;
    nix::unistd::setgid(original_gid).context("Failed to set GID")?;
    nix::unistd::setuid(original_uid).context("Failed to set UID")?;

    info!(
        "Helper: Successfully dropped privileges (now running as UID={}, GID={})",
        nix::unistd::getuid(),
        nix::unistd::getgid()
    );

    let tailscaled_pid = systemd::get_tailscaled_pid().await.ok();
    // Loop accepting new connections
    loop {
        debug!("Helper: awaiting new connection");
        let (mut client_stream, _) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;
        debug!("Helper: accepted new connection");

        tokio::spawn(async move {
            match handle_client_connection(&mut client_stream, tailscaled_pid).await {
                Ok(_) => {
                    info!("Helper: Client connection handled successfully");
                }
                Err(e) => {
                    error!("Helper: Error handling client connection: {:#}", e);
                }
            }
        });
    }
}

fn verify_peer_credentials(client_stream: &UnixStream) -> anyhow::Result<()> {
    let peer_cred = client_stream
        .peer_cred()
        .context("Failed to get peer credentials")?;

    let current_uid = nix::unistd::getuid();
    let peer_uid = Uid::from_raw(peer_cred.uid());

    if peer_uid != current_uid && !peer_uid.is_root() {
        warn!(
            "Helper: Rejecting connection from UID {} (we are UID {})",
            peer_uid, current_uid
        );
        anyhow::bail!("Connection from unauthorized user");
    }

    debug!(
        "Helper: Accepted connection from UID {} (we are UID {})",
        peer_uid, current_uid
    );

    Ok(())
}

async fn handle_client_connection(
    client_stream: &mut UnixStream,
    tailscaled_pid: Option<u32>,
) -> anyhow::Result<()> {
    // Verify peer credentials - only allow connections from the same user or root
    verify_peer_credentials(client_stream)?;

    // Receive the JSON message along with file descriptors via recvmsg
    let res = recv_exec_request(client_stream).await?;

    if res.is_none() {
        info!("Helper: No data received, client disconnected");
        return Ok(());
    }

    let (exec_request, received_fds) = res.unwrap();

    info!(
        "Helper: Received execution request for {:?} with {} args and {} fds",
        exec_request.executable,
        exec_request.args.len(),
        received_fds.len()
    );

    // Verify we received the expected number of FDs
    if received_fds.len() != exec_request.fd_targets.len() {
        anyhow::bail!(
            "Expected {} FDs but received {}",
            exec_request.fd_targets.len(),
            received_fds.len()
        );
    }

    if matches!((tailscaled_pid, exec_request.cur_tailscaled_pid), (Some(t), Some(c)) if t != c) {
        warn!(
            "Tailscaled PID has changed (was {:?}, now {:?}), refusing to execute and exiting",
            exec_request.cur_tailscaled_pid, tailscaled_pid
        );

        client_stream
            .write_all(b"ST")
            .await
            .context("Failed to send stale acknowledgment")?;
        exit(0);
    }

    // Fork and execute the command
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            debug!("Helper: Forked child process with PID: {}", child);

            // Send acknowledgment back to client
            client_stream
                .write_all(b"OK")
                .await
                .context("Failed to send acknowledgment")?;

            Ok(())
        }
        ForkResult::Child => {
            // In child process - create new session to detach from parent
            // This ensures that if ns-helper exits, this child won't receive signals
            if let Err(e) = nix::unistd::setsid() {
                error!("Helper child: Failed to create new session: {}", e);
                exit(1);
            }

            // Execute the command
            if let Err(e) = execute_in_child(exec_request, received_fds) {
                error!("Helper child: Failed to execute: {:#}", e);
                exit(1);
            }
            unreachable!("execvpe does not return on success");
        }
    }
}

async fn recv_exec_request(
    socket: &UnixStream,
) -> anyhow::Result<Option<(ExecRequest, Vec<OwnedFd>)>> {
    use nix::sys::socket::{recvmsg, MsgFlags};
    use std::io::IoSliceMut;

    const MAX_FDS: usize = 16;
    let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buffer = cmsg_space!([RawFd; MAX_FDS]);

    debug!("Helper: Waiting to receive execution request with FDs");

    let (bytes_read, fds) = socket
        .async_io(Interest::READABLE, || {
            let socket_fd = socket.as_raw_fd();
            let msg = recvmsg::<()>(
                socket_fd,
                &mut iov,
                Some(&mut cmsg_buffer),
                MsgFlags::empty(),
            )?;

            let bytes = msg.bytes;

            // Extract file descriptors from control messages
            let mut received_fds = Vec::new();
            for cmsg in msg.cmsgs()? {
                if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
                    for fd in fds {
                        received_fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                }
            }

            Ok((bytes, received_fds))
        })
        .await
        .context("Failed to receive execution request")?;

    debug!("Helper: Received {} bytes", bytes_read);
    if bytes_read == 0 {
        return Ok(None);
    }

    // Parse the JSON
    let exec_request: ExecRequest =
        serde_json::from_slice(&buf[..bytes_read]).context("Failed to parse execution request")?;

    debug!(
        "Helper: Received {} bytes and {} FDs",
        bytes_read,
        fds.len()
    );

    Ok(Some((exec_request, fds)))
}

fn execute_in_child(req: ExecRequest, received_fds: Vec<OwnedFd>) -> anyhow::Result<()> {
    // Collect the raw FDs we need to preserve
    let preserve_fds: Vec<RawFd> = received_fds.iter().map(|fd| fd.as_raw_fd()).collect();

    // Close all file descriptors except the ones we received
    debug!("Helper child: Closing all file descriptors except received ones");
    let max_fd = if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        dir.filter_map(|entry| {
            let entry = entry.ok()?;
            let fd = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
            Some(fd)
        })
        .max()
        .unwrap_or(1024)
    } else {
        // Fallback if /proc is not available
        1024
    };

    for fd in 0..=max_fd {
        // Don't close the FDs we need to preserve
        if !preserve_fds.contains(&fd) {
            let _ = close(fd);
        }
    }

    // Now dup2 the received FDs to their target positions
    debug!(
        "Helper child: Setting up {} file descriptors",
        received_fds.len()
    );
    for (i, target_fd) in req.fd_targets.iter().enumerate() {
        let source_fd = received_fds[i].as_raw_fd();
        if source_fd == *target_fd {
            debug!(
                "Helper child: FD {} is already at target position {}, skipping dup2",
                source_fd, target_fd
            );
            continue;
        }
        debug!("Helper child: dup2({} -> {})", source_fd, target_fd);
        let result = unsafe { nix::libc::dup2(source_fd, *target_fd) };
        if result == -1 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("Failed to dup2 fd {} to {}: {}", source_fd, target_fd, err);
        }
    }

    // Close the original received FDs (we've dup2'd them to their targets)
    for (i, fd) in received_fds.into_iter().enumerate() {
        // Only close if it wasn't already at the target position
        if fd.as_raw_fd() != req.fd_targets[i] {
            drop(fd);
        }
    }

    // Convert args to CStrings
    let args_cstr: Vec<CString> = req
        .args
        .iter()
        .map(|arg| CString::new(arg.as_bytes()).context("Failed to convert argument to CString"))
        .collect::<Result<Vec<_>, _>>()?;

    // Convert environment to CStrings in "KEY=VALUE" format
    let mut env_cstr: Vec<CString> = Vec::new();

    // First, inherit existing environment variables
    for (key, value) in std::env::vars_os() {
        if key == "LOGNAME" || key == "USER" || key == "HOME" {
            // We'll override these later
            continue;
        }
        let env_string = format!("{}={}", key.to_string_lossy(), value.to_string_lossy());
        if let Ok(c_str) = CString::new(env_string.as_bytes()) {
            env_cstr.push(c_str);
        }
    }

    // pkexec sets LOGNAME, USER, HOME... Let's override them
    // get the username of PKEXEC_UID
    if let Some(user) = users::get_user_by_uid(users::get_current_uid()) {
        let username = user.name().to_string_lossy();
        let home_dir = user.home_dir().to_string_lossy();

        env_cstr.push(CString::new(format!("LOGNAME={}", username.as_ref()))?);
        env_cstr.push(CString::new(format!("USER={}", username.as_ref()))?);
        env_cstr.push(CString::new(format!("HOME={}", home_dir.as_ref()))?);
    }

    // Then, add/override with the provided environment variables
    for (key, value) in &req.env {
        let env_string = format!("{}={}", key.to_string_lossy(), value.to_string_lossy());

        // Remove any existing entry for this key
        env_cstr.retain(|s| {
            let s_str = s.to_string_lossy();
            !s_str.starts_with(&format!("{}=", key.to_string_lossy()))
        });

        if let Ok(c_str) = CString::new(env_string.as_bytes()) {
            env_cstr.push(c_str);
        }
    }

    // Convert executable path to CString
    let exec_path = CString::new(req.executable.as_os_str().as_bytes())
        .context("Failed to convert executable path to CString")?;

    // Execute the program
    debug!("Helper child: Executing {:?}", exec_path);
    execvpe(&exec_path, &args_cstr, &env_cstr)
        .map_err(|e| anyhow::anyhow!("Failed to execute: {}", e))?;

    unreachable!("execvpe does not return on success");
}

fn copy_var(name: &str) -> CString {
    if let Ok(val) = std::env::var(name) {
        CString::new(format!("{}={}", name, val)).unwrap()
    } else {
        CString::new(format!("{}=", name)).unwrap()
    }
}

fn copy_all_xdg() -> Vec<CString> {
    let mut vars = Vec::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("XDG_") {
            vars.push(CString::new(format!("{}={}", key, value)).unwrap());
        }
    }
    vars
}

async fn start_helper_process(socket_path: &Path) -> anyhow::Result<NamespaceLauncher> {
    info!("Launching helper process with elevated privileges");

    const STACK_SIZE: usize = 1024 * 1024; // 1 MB should be enough
    let mut stack: Vec<u8> = vec![0; STACK_SIZE];

    let current_exe = std::env::current_exe()?;

    let mut args: Vec<CString> = vec![
        c"/usr/bin/pkexec".into(),
        c"env".into(),
        copy_var("DISPLAY"),
        copy_var("XAUTHORITY"),
        copy_var("DBUS_SESSION_BUS_ADDRESS"),
        copy_var("SSH_AUTH_SOCK"),
        c"GTK_IM_MODULE=xim".into(), // ibus goes through unshared abstract socket
        c"QT_IM_MODULE=xim".into(),
        c"XMODIFIERS=@im=none".into(),
    ];
    args.extend(copy_all_xdg());
    args.extend(vec![
        CString::new(current_exe.as_os_str().as_bytes()).unwrap(),
        c"-v".into(),
        CString::new(log::max_level().to_int().to_string().as_bytes()).unwrap(),
        c"ns-helper".into(),
        c"--abstract-path".into(),
        CString::new(socket_path.as_os_str().as_bytes()).unwrap(),
    ]);

    let _child_pid = unsafe {
        clone(
            Box::new(move || {
                // This is executed in the child process
                debug!("Helper pre-exec: executing with pkexec");

                let empty_env: &[&CStr] = &[];
                match execvpe(&args[0], &args, empty_env) {
                    Ok(_) => {
                        unreachable!("If execvpe succeeds, it does not return")
                    }
                    Err(e) => {
                        error!("Helper pre-exec: execvpe() failed: {}", e);
                        1
                    }
                }
            }),
            &mut stack,
            CloneFlags::CLONE_VFORK,
            None,
        )
    }
    .context("Failed to clone process")?;

    // Probe the helper process to ensure it's ready
    let _stream = connect_abstract_unix(socket_path, 30 * 4, Duration::from_millis(250))
        .await
        .context("Failed to connect to abstract socket")?;

    debug!("Helper process is ready");

    Ok(NamespaceLauncher {
        socket_path: socket_path.to_path_buf(),
    })
}

pub struct NamespaceLauncher {
    socket_path: PathBuf,
}

pub enum LaunchResult {
    Success,
    Stale,
}
impl NamespaceLauncher {
    pub async fn new(socket_path: &Path) -> anyhow::Result<Self> {
        let res = connect_abstract_unix(socket_path, 1, Duration::from_millis(0)).await;
        match res {
            Ok(_) => Ok(Self {
                socket_path: socket_path.to_path_buf(),
            }),
            Err(err) => {
                info!(
                    "Namespace helper process not running, launching it: {}",
                    err
                );
                start_helper_process(socket_path).await
            }
        }
    }

    pub async fn launch_in_ns(
        &self,
        executable: PathBuf,
        args: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
        fds: Vec<(RawFd, impl AsRawFd)>,
    ) -> anyhow::Result<LaunchResult> {
        info!("Sending execution request for {:?}", executable);

        // Connect to the helper process
        let stream = connect_abstract_unix(&self.socket_path, 10, Duration::from_millis(100))
            .await
            .context("Failed to connect to helper process")?;

        // Extract target FD numbers
        let fd_targets: Vec<RawFd> = fds.iter().map(|(target, _)| *target).collect();

        // Build the execution request
        let exec_request = ExecRequest {
            executable,
            args,
            env,
            fd_targets,
            cur_tailscaled_pid: systemd::get_tailscaled_pid().await.ok(),
        };

        // Serialize to JSON
        let json_bytes =
            serde_json::to_vec(&exec_request).context("Failed to serialize execution request")?;

        // Send the message with FDs using sendmsg
        send_exec_request(&stream, &json_bytes, &fds).await?;

        // Wait for acknowledgment
        let mut ack_buf = [0u8; 2];
        stream
            .async_io(Interest::READABLE, || {
                let mut buf = [0u8; 2];
                let n = nix::unistd::read(&stream, &mut buf)?;
                if n == 2 {
                    ack_buf = buf;
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Short read on acknowledgment",
                    ))
                }
            })
            .await
            .context("Failed to read acknowledgment")?;

        if &ack_buf == b"OK" {
            info!("Helper acknowledged execution request");
            Ok(LaunchResult::Success)
        } else if &ack_buf == b"ST" {
            warn!("Helper reported stale tailscaled PID, not executing");
            Ok(LaunchResult::Stale)
        } else {
            anyhow::bail!("Unexpected acknowledgment from helper: {:?}", ack_buf);
        }
    }
}

async fn send_exec_request<F: AsRawFd>(
    socket: &UnixStream,
    json_bytes: &[u8],
    fds: &[(RawFd, F)],
) -> anyhow::Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::io::IoSlice;

    debug!("Sending execution request with {} FDs", fds.len());

    // Collect raw FDs for SCM_RIGHTS
    let raw_fds: Vec<RawFd> = fds.iter().map(|(_, fd)| fd.as_raw_fd()).collect();

    let iov = [IoSlice::new(json_bytes)];
    let cmsgs = [ControlMessage::ScmRights(&raw_fds)];

    socket
        .writable()
        .await
        .context("Failed while waiting for socket to be writable")?;

    socket
        .try_io(Interest::WRITABLE, || {
            let socket_fd = socket.as_raw_fd();
            sendmsg::<()>(socket_fd, &iov, &cmsgs, MsgFlags::empty(), None)?;
            Ok(())
        })
        .context("Failed to send execution request with FDs")?;

    debug!("Sent {} bytes with {} FDs", json_bytes.len(), fds.len());

    Ok(())
}
