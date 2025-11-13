use anyhow::Context;
use futures_util::TryStreamExt;
use log::{debug, error, info, trace, warn};
use netlink_sys::AsyncSocketExt;
use netlink_sys::{protocols::NETLINK_NETFILTER, AsyncSocket, SocketAddr, TokioSocket};
use nftnl::expr::Expression;
use nftnl::nftnl_sys::libc;
use nftnl::{nft_expr, Chain, ProtoFamily, Rule, Table};
use nftnl::{nftnl_sys as sys, Batch};
use nix::mount::{mount, MsFlags};
use nix::sched::{clone, setns, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::stat::Mode;
use nix::unistd::mkdir;
use rtnetlink::{new_connection, Handle, LinkUnspec, LinkVeth, RouteMessageBuilder};
use static_assertions::const_assert_eq;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::future::Future;
use std::io::{IoSlice, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

const VETH_NAME_HOST: &str = "veth-ts-host";
const VETH_NAME_NS: &str = "veth-ts-ns";

// mount_attr structure for mount_setattr syscall
#[repr(C)]
#[derive(Debug, Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

async fn create_veth_pair(handle: &Handle, ts_ns: &Namespace) -> anyhow::Result<()> {
    info!(
        "Creating veth pair: {} and {}",
        VETH_NAME_HOST, VETH_NAME_NS
    );

    // create interfaces
    let mut retried = false;
    loop {
        let res = handle
            .link()
            .add(LinkVeth::new(VETH_NAME_HOST, VETH_NAME_NS).build())
            .execute()
            .await;

        if let err @ Err(rtnetlink::Error::NetlinkError(rtnetlink::packet_core::ErrorMessage {
            code: Some(errno),
            ..
        })) = res
        {
            if errno.get() == -libc::EEXIST && !retried {
                info!("Veth pair already exists, deleting and recreating");

                let idx = ifname_to_index(handle, VETH_NAME_HOST)
                    .await
                    .context(format!("Finding existing interface {}", VETH_NAME_HOST))?;

                info!("Deleting existing interface: {}", VETH_NAME_HOST);
                handle
                    .link()
                    .del(idx)
                    .execute()
                    .await
                    .context(format!("Deleting existing interface {}", VETH_NAME_HOST))?;
                retried = true;
                continue; // try again
            } else {
                err.context(format!(
                    "Creating veth pair {} and {}",
                    VETH_NAME_HOST, VETH_NAME_NS
                ))?;
            }
        } else {
            debug!("Veth pair created successfully");
        }
        break;
    }

    // get their indices
    debug!("Retrieving interface indices");
    let veth_host_idx = ifname_to_index(handle, VETH_NAME_HOST).await?;
    let veth_ns_idx = ifname_to_index(handle, VETH_NAME_NS).await?;
    debug!(
        "Retrieved indices: host={}, ns={}",
        veth_host_idx, veth_ns_idx
    );

    // configure the host side
    info!("Configuring host side interface ({})", VETH_NAME_HOST);
    bring_up_interface(handle, veth_host_idx).await?;
    debug!("Adding IP address 172.31.0.1/30 to {}", VETH_NAME_HOST);
    handle
        .address()
        .add(veth_host_idx, "172.31.0.1".parse()?, 30)
        .execute()
        .await
        .context(format!("Adding address to {}", VETH_NAME_HOST))?;
    debug!("Adding IPv6 address fc00::1/64 to {}", VETH_NAME_HOST);
    handle
        .address()
        .add(veth_host_idx, "fc00::1".parse()?, 64)
        .execute()
        .await
        .context(format!("Adding IPv6 address to {}", VETH_NAME_HOST))?;

    info!("Moving interface {} to namespace", VETH_NAME_NS);
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(veth_ns_idx)
                .setns_by_fd(ts_ns.0.as_raw_fd())
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("Failed to move interface {} to namespace", VETH_NAME_NS))?;
    info!("Successfully moved interface to namespace");

    Ok(())
}

async fn configure_veth_ns(handle: &Handle, veth_ns_idx: u32) -> anyhow::Result<()> {
    // configure the ns side
    info!("Configuring namespace side interface ({})", VETH_NAME_NS);
    bring_up_interface(handle, veth_ns_idx).await?;
    debug!("Adding IP address 172.31.0.2/30 to {}", VETH_NAME_NS);
    handle
        .address()
        .add(veth_ns_idx, "172.31.0.2".parse()?, 30)
        .execute()
        .await
        .context(format!("Adding address to {}", VETH_NAME_NS))?;
    debug!("Adding IPv6 address fc00::2/64 to {}", VETH_NAME_NS);
    handle
        .address()
        .add(veth_ns_idx, "fc00::2".parse()?, 64)
        .execute()
        .await
        .context(format!("Adding IPv6 address to {}", VETH_NAME_NS))?;
    Ok(())
}

async fn add_default_route(handle: &Handle) -> anyhow::Result<()> {
    info!("Adding IPv4 default route via 172.31.0.1");
    handle
        .route()
        .add(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .gateway("172.31.0.1".parse()?)
                .build(),
        )
        .execute()
        .await
        .context("Error adding IPv4 default route")?;
    debug!("IPv4 default route added successfully");

    info!("Adding IPv6 default route via fc00::1");
    handle
        .route()
        .add(
            RouteMessageBuilder::<Ipv6Addr>::new()
                .gateway("fc00::1".parse()?)
                .build(),
        )
        .execute()
        .await
        .context("Error adding IPv6 default route")?;
    debug!("IPv6 default route added successfully");

    Ok(())
}

struct Namespace(OwnedFd);
impl Namespace {
    fn current_net() -> anyhow::Result<Self> {
        trace!("Getting current network namespace");
        let file = File::open("/proc/self/ns/net").context("Failed to open /proc/self/ns/net")?;
        debug!("Successfully retrieved current network namespace");
        Ok(Self(file.into()))
    }
}
impl From<File> for Namespace {
    fn from(fd: File) -> Self {
        Self(fd.into())
    }
}

struct BoundNamespaces {
    net: Namespace,
    #[allow(dead_code)]
    mnt: Namespace,
}
const RUN_DIR: &str = "/var/run/tailscale-net";
const NS_DIR: &str = "/var/run/tailscale-net/ns";
pub const NET_NS_PATH: &str = "/var/run/tailscale-net/ns/net";
pub const MNT_NS_PATH: &str = "/var/run/tailscale-net/ns/mnt";

fn create_namespace() -> anyhow::Result<BoundNamespaces> {
    // create a directory for the namespace files
    let rundir_path = Path::new(RUN_DIR);
    if !rundir_path.exists() {
        debug!("Creating tailscale network runtime directory: {}", RUN_DIR);
        mkdir(rundir_path, Mode::from_bits(0o755).unwrap())
            .with_context(|| format!("Failed to create netns directory: {:?}", rundir_path))?;
    } else {
        debug!("Directory already exists: {}", RUN_DIR);
    }

    // create /var/run/tailscale-net/ns and mount a private tmpfs there
    let nsdir_path = Path::new(NS_DIR);
    if !nsdir_path.exists() {
        debug!("Creating namespace directory: {}", NS_DIR);
        mkdir(nsdir_path, Mode::from_bits(0o755).unwrap())
            .with_context(|| format!("Failed to create namespace directory: {:?}", nsdir_path))?;
    } else {
        debug!("Namespace directory already exists: {}", NS_DIR);
    }
    mount(
        None::<&str>,
        NS_DIR,
        Some("tmpfs"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )
    .map_err(|e| anyhow::anyhow!("Failed to mount tmpfs at {}: {}", NS_DIR, e))?;

    mount(
        None::<&str>,
        NS_DIR,
        None::<&str>,
        MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| anyhow::anyhow!("Failed to make mount at {} private: {}", NS_DIR, e))?;

    // create the namespace files
    debug!("Creating network namespace file: {}", NET_NS_PATH);
    File::create(NET_NS_PATH)
        .with_context(|| format!("Failed to create network namespace file: {}", NET_NS_PATH))?;
    debug!("Creating mount namespace file: {}", MNT_NS_PATH);
    File::create(MNT_NS_PATH)
        .with_context(|| format!("Failed to create mount namespace file: {}", MNT_NS_PATH))?;

    // to signal the child when it can exit
    let (pipe_reader, pipe_writer) =
        nix::unistd::pipe().context("Failed to create pipe for parent-child communication")?;

    // allocate stack for the child process
    const STACK_SIZE: usize = 1024 * 1024; // 1 MB
    let mut stack: Vec<u8> = vec![0; STACK_SIZE];

    debug!("Cloning process to create new namespaces");
    let child_pid = unsafe {
        clone(
            Box::new(move || child_create_ts_ns(RUN_DIR, pipe_reader.as_raw_fd())),
            &mut stack,
            CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET,
            Some(Signal::SIGCHLD as i32),
        )
    }
    .context("Failed to clone")?;
    debug!("Parent: Child process created with PID: {}", child_pid);

    // Parent process will now perform the bind mounts
    debug!("Parent: Binding namespaces from child PID {}", child_pid);

    // Path to child's namespace files
    let child_net_ns = format!("/proc/{}/ns/net", child_pid);
    let child_mnt_ns = format!("/proc/{}/ns/mnt", child_pid);

    // Bind mount network namespace
    debug!(
        "Parent: Binding child's network namespace to {}",
        NET_NS_PATH
    );
    mount(
        Some(child_net_ns.as_str()),
        NET_NS_PATH,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "Failed to bind mount child's network namespace at {} to {}",
            child_net_ns, NET_NS_PATH
        )
    })?;

    // Bind mount mount namespace
    debug!("Parent: Binding child's mount namespace to {}", MNT_NS_PATH);
    mount(
        Some(child_mnt_ns.as_str()),
        MNT_NS_PATH,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "Failed to bind mount child's mount namespace at {} to {}",
            child_mnt_ns, MNT_NS_PATH
        )
    })?;

    // Signal the child to continue by writing a byte to the pipe
    debug!("Parent: Signaling child to continue");
    nix::unistd::write(&pipe_writer, &[1]).context("Failed to signal child process")?;

    drop(pipe_writer);

    // Wait for child to finish
    debug!("Parent: Waiting for child process to complete");
    let status = nix::sys::wait::waitpid(child_pid, None).context("Failed to wait for child")?;
    debug!("Parent: Child process completed with status: {:?}", status);

    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => {
            if code != 0 {
                error!("Child exited with non-zero code {}", code);
                anyhow::bail!("Child exited with code {}", code);
            }
            debug!("Child completed successfully with exit code 0");
        }
        _ => {
            error!("Child exited with unexpected status: {:?}", status);
            anyhow::bail!("Child exited with status {:?}", status);
        }
    }

    info!("Opening namespace file descriptors");
    debug!("Opening network namespace at {}", NET_NS_PATH);
    let net_namespace = File::open(NET_NS_PATH)
        .with_context(|| format!("Failed to open network namespace file: {}", NET_NS_PATH))?;

    debug!("Opening mount namespace at {}", MNT_NS_PATH);
    let mnt_namespace = File::open(MNT_NS_PATH)
        .with_context(|| format!("Failed to open mount namespace file: {}", MNT_NS_PATH))?;

    info!("Successfully created and bound to new namespaces");
    Ok(BoundNamespaces {
        net: net_namespace.into(),
        mnt: mnt_namespace.into(),
    })
}

fn child_create_ts_ns(ns_path_prefix: &str, sync_pipe: i32) -> isize {
    debug!("Child: Process started to create tailscale namespaces");

    if let Err(e) = setup_child_namespace(ns_path_prefix, sync_pipe) {
        error!("Failed to setup namespace: {:#}", e);
        eprintln!("Failed to setup namespace: {:#}", e);
        return 1;
    }

    debug!("Child process completed successfully");
    0
}

fn setup_child_namespace(run_dir: &str, sync_pipe: i32) -> anyhow::Result<()> {
    // do not propagate mounts to the parent
    debug!("Child: Setting mount propagation to MS_PRIVATE");
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_SLAVE,
        None::<&str>,
    )
    .context("Failed to change mount propagation")?;

    // Wait for parent to signal that it's done binding our namespaces
    debug!("Child: Waiting for parent to bind namespaces...");
    let mut buf = [0u8; 1];
    let sync_pipe_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(sync_pipe) };
    let bytes_read =
        nix::unistd::read(sync_pipe_fd, &mut buf).context("Failed to read from sync pipe")?;

    if bytes_read != 1 || buf[0] != 1 {
        return Err(anyhow::anyhow!("Unexpected data from parent sync pipe"));
    }

    debug!("Child: Parent has bound namespaces, continuing setup");
    nix::unistd::close(sync_pipe).context("Failed to close sync pipe")?;

    // create a resolv.conf
    let tmp_resolv = format!("{}/{}", run_dir, "resolv.conf");
    debug!("Child: Creating custom resolv.conf at {}", tmp_resolv);
    let mut file = File::create(&tmp_resolv)
        .with_context(|| format!("Failed to create resolv.conf at {}", tmp_resolv))?;

    debug!("Child: Writing nameserver entries to resolv.conf");
    // we could consider copying the host's resolv.conf entries here instead
    writeln!(file, "nameserver 8.8.8.8\nnameserver 1.1.1.1")
        .context("Failed to write nameserver entries to resolv.conf")?;

    // bind mount the resolv.conf using new mount API to avoid following symlinks
    // The traditional mount() syscall would follow the symlink, but we want to
    // mount over the symlink itself so changes don't propagate to the parent namespace
    debug!("Child: Mounting custom resolv.conf to /etc/resolv.conf using new mount API");

    let source_path = CString::new(tmp_resolv.as_bytes()).context("Invalid source path")?;

    // Step 1: open_tree() with AT_SYMLINK_NOFOLLOW to get fd for source
    let mount_fd = unsafe {
        let fd = libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            source_path.as_ptr(),
            libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW | libc::OPEN_TREE_CLONE as i32,
        );
        if fd < 0 {
            anyhow::bail!("open_tree failed: {}", std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd as i32)
    };

    // Step 2: mount_setattr() to set MS_PRIVATE propagation
    let attr = MountAttr {
        propagation: libc::MS_PRIVATE,
        ..Default::default()
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount_fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };

    if result < 0 {
        anyhow::bail!("mount_setattr failed: {}", std::io::Error::last_os_error());
    }

    // Step 3: move_mount() to attach to /etc/resolv.conf without following symlink
    let result = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount_fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_FDCWD,
            c"/etc/resolv.conf".as_ptr(),
            libc::MOVE_MOUNT_F_EMPTY_PATH,
        )
    };

    if result < 0 {
        anyhow::bail!("move_mount failed: {}", std::io::Error::last_os_error());
    }

    debug!("Child: Successfully mounted resolv.conf without following symlink");

    Ok(())
}

async fn ifname_to_index(handle: &Handle, if_name: &str) -> anyhow::Result<u32> {
    trace!("Looking up index for interface: {}", if_name);
    let mut links = handle.link().get().match_name(if_name.to_owned()).execute();
    let link = match links.try_next().await {
        Ok(Some(link)) => {
            debug!("Found interface {}: index={}", if_name, link.header.index);
            link
        }
        Ok(None) => {
            warn!("Interface {} not found", if_name);
            anyhow::bail!("Interface {} not found", if_name)
        }
        Err(e) => {
            error!("Error finding interface {}: {}", if_name, e);
            anyhow::bail!("Error finding interface {}: {}", if_name, e)
        }
    };

    Ok(link.header.index)
}

async fn bring_up_interface(handle: &Handle, if_index: u32) -> anyhow::Result<()> {
    debug!("Bringing up interface with index {}", if_index);
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(if_index)
                .up() // This sets the interface to the "up" state
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("Failed to bring up interface {}", if_index))?;
    debug!("Successfully brought up interface {}", if_index);

    Ok(())
}

async fn enter_ns<O, FunRet, FutRetOutput>(ns: &Namespace, future: FunRet) -> anyhow::Result<O>
where
    FunRet: Future<Output = FutRetOutput>,
    FutRetOutput: Into<anyhow::Result<O>>,
{
    debug!("Entering network namespace");
    let cur_ns = Namespace::current_net()?;
    trace!("Saved current network namespace");

    debug!("Switching to target namespace");
    setns(ns.0.as_fd(), CloneFlags::CLONE_NEWNET)?;
    debug!("Successfully switched to target namespace");

    debug!("Executing function in namespace");
    let res: anyhow::Result<O> = future.await.into();

    debug!("Returning to original namespace");
    setns(cur_ns.0, CloneFlags::CLONE_NEWNET)?;
    debug!("Successfully returned to original namespace");

    res
}

// Unique identifier for our tailscale NAT rules
const TS_NAT_RULE_MARKER: &[u8] = b"tailscale-systray-nat-v1";
const TS_NAT6_RULE_MARKER: &[u8] = b"tailscale-systray-nat6-v1";
const TS_FORWARD_OUT_RULE_MARKER: &[u8] = b"tailscale-systray-fwd-out-v1";
const TS_FORWARD_IN_RULE_MARKER: &[u8] = b"tailscale-systray-fwd-in-v1";
const TS_FORWARD6_OUT_RULE_MARKER: &[u8] = b"tailscale-systray-fwd6-out-v1";
const TS_FORWARD6_IN_RULE_MARKER: &[u8] = b"tailscale-systray-fwd6-in-v1";

// Netlink message parsing helpers (these are macros in C but we implement as functions)
const NLMSG_ALIGNTO: u32 = 4;

#[inline]
unsafe fn nlmsg_align(len: u32) -> u32 {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[inline]
unsafe fn nlmsg_ok(nlh: *const libc::nlmsghdr, len: i32) -> bool {
    len >= std::mem::size_of::<libc::nlmsghdr>() as i32
        && (*nlh).nlmsg_len >= std::mem::size_of::<libc::nlmsghdr>() as u32
        && (*nlh).nlmsg_len as i32 <= len
}

#[inline]
unsafe fn nlmsg_next(nlh: *const libc::nlmsghdr) -> *const libc::nlmsghdr {
    let offset = nlmsg_align((*nlh).nlmsg_len);
    (nlh as *const u8).add(offset as usize) as *const libc::nlmsghdr
}

// Extension trait for TokioSocket to support sendmsg with iovecs
trait TokioSocketExt {
    async fn sendmsg<'a, M>(&mut self, messages: M, addr: &SocketAddr) -> std::io::Result<usize>
    where
        M: IntoIterator<Item = &'a [u8]>;
}

impl TokioSocketExt for TokioSocket {
    async fn sendmsg<'a, M>(&mut self, messages: M, addr: &SocketAddr) -> std::io::Result<usize>
    where
        M: IntoIterator<Item = &'a [u8]>,
    {
        let iovecs: Vec<IoSlice> = messages.into_iter().map(IoSlice::new).collect();

        // TokioSocket is TokioSocket(AsyncFd<Socket>), so we can transmute it
        // to access the AsyncFd's async_io method
        let async_fd: &mut tokio::io::unix::AsyncFd<netlink_sys::Socket> =
            unsafe { std::mem::transmute(self) };

        async_fd
            .async_io(tokio::io::Interest::WRITABLE, |inner| {
                let fd = inner.as_raw_fd();

                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_name = addr as *const _ as *mut libc::c_void;
                msg.msg_namelen = std::mem::size_of::<SocketAddr>() as u32;
                msg.msg_iov = iovecs.as_ptr() as *mut libc::iovec;
                msg.msg_iovlen = iovecs.len();

                let result = unsafe { libc::sendmsg(fd, &msg, 0) };

                if result < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            })
            .await
    }
}

// Helper function to create and configure a netlink netfilter socket
fn create_netfilter_socket() -> anyhow::Result<netlink_sys::TokioSocket> {
    let mut socket =
        TokioSocket::new(NETLINK_NETFILTER).context("Failed to create netlink socket")?;

    // Set NETLINK_EXT_ACK option for better error messages
    unsafe {
        let fd = socket.socket_mut().as_raw_fd();
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_NETLINK,
            libc::NETLINK_EXT_ACK,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let mut addr = SocketAddr::new(0, 0);
    socket
        .socket_mut()
        .bind(&addr)
        .context("Failed to bind netlink socket")?;

    socket
        .socket_mut()
        .get_address(&mut addr)
        .context("Failed to get socket address")?;

    Ok(socket)
}

// XT Target expression for iptables compatibility
pub struct XtTarget {
    name: &'static CStr,
    is_ipv6: bool,
}

impl XtTarget {
    pub fn masquerade() -> Self {
        Self {
            name: c"MASQUERADE",
            is_ipv6: false,
        }
    }

    pub fn masquerade_v6() -> Self {
        Self {
            name: c"MASQUERADE",
            is_ipv6: true,
        }
    }
}

// target info buffer for MASQUERADE xt target (24 bytes for IPv4)
const XT_TG_INFO: [u8; 24] = [
    1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// target info buffer for MASQUERADE xt target (40 bytes for IPv6)
const XT_TG_INFO_V6: [u8; 40] = [
    0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
];

impl Expression for XtTarget {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            debug!("XtTarget: Allocating xt target expression");
            let expr = sys::nftnl_expr_alloc(c"target".as_ptr());
            if expr.is_null() {
                error!("XtTarget: nftnl_expr_alloc returned null for 'target'");
                return std::ptr::null_mut();
            }

            // set target name - nftnl_expr_set_str copies the string, so this is safe
            sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_TG_NAME as u16, self.name.as_ptr());

            // set revision to 0
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_TG_REV as u16, 0);

            // Use the correct target info buffer based on IPv4/IPv6
            let (tg_info_ptr, tg_info_len) = if self.is_ipv6 {
                (XT_TG_INFO_V6.as_ptr(), XT_TG_INFO_V6.len())
            } else {
                (XT_TG_INFO.as_ptr(), XT_TG_INFO.len())
            };

            let tg_info_copy = libc::malloc(tg_info_len);
            std::ptr::copy_nonoverlapping(tg_info_ptr, tg_info_copy as *mut _, tg_info_len);

            // set target info (takes ownership of the data buffer)
            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_TG_INFO as u16,
                tg_info_copy as *const _,
                tg_info_len as u32,
            );

            expr
        }
    }
}

// Connection tracking state bits (from nf_conntrack_common.h)
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum NfCtState {
    Invalid = 0x0001,     // NF_CT_STATE_INVALID_BIT
    Established = 0x0002, // NF_CT_STATE_BIT(IP_CT_ESTABLISHED)
    Related = 0x0004,     // NF_CT_STATE_BIT(IP_CT_RELATED)
    New = 0x0008,         // NF_CT_STATE_BIT(IP_CT_NEW)
    Untracked = 0x0040,   // NF_CT_STATE_UNTRACKED_BIT
}

// xt_conntrack match flags (from xt_conntrack.h)
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum XtConntrackFlags {
    State = 1 << 0,        // XT_CONNTRACK_STATE
    Proto = 1 << 1,        // XT_CONNTRACK_PROTO
    OrigSrc = 1 << 2,      // XT_CONNTRACK_ORIGSRC
    OrigDst = 1 << 3,      // XT_CONNTRACK_ORIGDST
    ReplSrc = 1 << 4,      // XT_CONNTRACK_REPLSRC
    ReplDst = 1 << 5,      // XT_CONNTRACK_REPLDST
    Status = 1 << 6,       // XT_CONNTRACK_STATUS
    Expires = 1 << 7,      // XT_CONNTRACK_EXPIRES
    OrigSrcPort = 1 << 8,  // XT_CONNTRACK_ORIGSRC_PORT
    OrigDstPort = 1 << 9,  // XT_CONNTRACK_ORIGDST_PORT
    ReplSrcPort = 1 << 10, // XT_CONNTRACK_REPLSRC_PORT
    ReplDstPort = 1 << 11, // XT_CONNTRACK_REPLDST_PORT
    Direction = 1 << 12,   // XT_CONNTRACK_DIRECTION
}

// Matches the kernel's xt_conntrack_mtinfo3 structure (168 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
struct XtConntrackMtinfo3 {
    origsrc_addr: [u8; 16],
    origsrc_mask: [u8; 16],
    origdst_addr: [u8; 16],
    origdst_mask: [u8; 16],
    replsrc_addr: [u8; 16],
    replsrc_mask: [u8; 16],
    repldst_addr: [u8; 16],
    repldst_mask: [u8; 16],
    expires_min: u32,
    expires_max: u32,
    l4proto: u16,
    origsrc_port: u16,
    origdst_port: u16,
    replsrc_port: u16,
    repldst_port: u16,
    match_flags: u16,
    invert_flags: u16,
    state_mask: u16,
    status_mask: u16,
    origsrc_port_high: u16,
    origdst_port_high: u16,
    replsrc_port_high: u16,
    repldst_port_high: u16,
    _padding: [u8; 4], // Explicit padding to reach 168 bytes
}

const_assert_eq!(std::mem::size_of::<XtConntrackMtinfo3>(), 168);

pub struct XtConntrack3 {
    mtinfo: XtConntrackMtinfo3,
}

impl XtConntrack3 {
    // Match ESTABLISHED and RELATED states (verified: 0x02 | 0x04 = 0x06)
    pub fn conntrack_state_established_related() -> Self {
        let mtinfo = XtConntrackMtinfo3 {
            match_flags: XtConntrackFlags::State as u16,
            state_mask: NfCtState::Established as u16 | NfCtState::Related as u16,
            ..Default::default()
        };

        Self { mtinfo }
    }
}

impl Expression for XtConntrack3 {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            trace!("XtConntrack3: Allocating xt match expression for conntrack");
            let expr = sys::nftnl_expr_alloc(c"match".as_ptr());
            if expr.is_null() {
                error!("XtConntrack3: nftnl_expr_alloc returned null for 'match'");
                return std::ptr::null_mut();
            }

            sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_MT_NAME as u16, c"conntrack".as_ptr());
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_MT_REV as u16, 3);

            // Convert the structure to bytes
            let mt_info_ptr = &self.mtinfo as *const XtConntrackMtinfo3 as *const u8;
            let mt_info_len = std::mem::size_of::<XtConntrackMtinfo3>();

            let mt_info_copy = libc::malloc(mt_info_len);
            std::ptr::copy_nonoverlapping(mt_info_ptr, mt_info_copy as *mut u8, mt_info_len);

            sys::nftnl_expr_set(
                expr,
                sys::NFTNL_EXPR_MT_INFO as u16,
                mt_info_copy as *const _,
                mt_info_len as u32,
            );

            debug!(
                "XtConntrack3: Set match info (state_mask=0x{:04x}, match_flags=0x{:04x})",
                self.mtinfo.state_mask, self.mtinfo.match_flags
            );

            expr
        }
    }
}

async fn check_rule_exists(
    socket: &mut netlink_sys::TokioSocket,
    proto_family: u32,
    table: &CStr,
    chain: &CStr,
    marker: &[u8],
    proto_name: &str,
) -> anyhow::Result<bool> {
    use nftnl::nftnl_sys as sys;

    debug!(
        "Checking if {} rule already exists in {}/{}",
        proto_name,
        table.to_str().unwrap_or("?"),
        chain.to_str().unwrap_or("?")
    );

    // use nftnl_sys, we don't have high-level bindings for rule listing
    let (buffer, msg_len) = unsafe {
        let rule = sys::nftnl_rule_alloc();
        if rule.is_null() {
            anyhow::bail!("Failed to allocate nftnl_rule for GETRULE");
        }

        // Set the table and chain we want to query
        sys::nftnl_rule_set_str(rule, sys::NFTNL_RULE_TABLE as u16, table.as_ptr());
        sys::nftnl_rule_set_str(rule, sys::NFTNL_RULE_CHAIN as u16, chain.as_ptr());
        sys::nftnl_rule_set_u32(rule, sys::NFTNL_RULE_FAMILY as u16, proto_family);

        let mut buffer = vec![0u8; 4096];

        // Build netlink message header with GETRULE type and DUMP flag
        let nlh = sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut _,
            libc::NFT_MSG_GETRULE as u16,
            proto_family as u16,
            (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
            0, // seq
        );

        if nlh.is_null() {
            sys::nftnl_rule_free(rule);
            anyhow::bail!("Failed to build netlink header for GETRULE");
        }

        sys::nftnl_rule_nlmsg_build_payload(nlh, rule);

        let msg_len = (*nlh).nlmsg_len as usize;

        // Free the rule object - the message is now in the buffer
        sys::nftnl_rule_free(rule);

        (buffer, msg_len)
    };

    let kernel_addr = SocketAddr::new(0, 0);
    debug!("Sending {} GETRULE request ({} bytes)", proto_name, msg_len);
    socket
        .send_to(&buffer[..msg_len], &kernel_addr)
        .await
        .context(format!("Failed to send {} GETRULE request", proto_name))?;

    debug!("Waiting for {} GETRULE responses", proto_name);
    // Read responses with timeout
    let timeout_duration = std::time::Duration::from_secs(2);

    let mut found = false;

    loop {
        let recv_result = tokio::time::timeout(timeout_duration, socket.recv_from_full()).await;

        let (recv_buffer, _addr) = match recv_result {
            Ok(Ok((buf, addr))) => {
                debug!("Received netlink response ({} bytes)", buf.len());
                (buf, addr)
            }
            Ok(Err(e)) => {
                return Err(anyhow::anyhow!(
                    "Failed to receive {} GETRULE response: {}",
                    proto_name,
                    e
                ));
            }
            Err(_) => {
                // Timeout - no more messages
                debug!(
                    "Timeout waiting for responses, {} rule found: {}",
                    proto_name, found
                );
                return Ok(found);
            }
        };

        // Parse netlink messages using netlink iteration helpers
        unsafe {
            let mut nlh = recv_buffer.as_ptr() as *const libc::nlmsghdr;
            let mut remaining = recv_buffer.len() as i32;

            // Iterate through netlink messages
            while nlmsg_ok(nlh, remaining) {
                let nlmsg_type = (*nlh).nlmsg_type;
                let nlmsg_len = (*nlh).nlmsg_len;

                debug!("Parsing message: type={}, len={}", nlmsg_type, nlmsg_len);

                // Check for NLMSG_DONE
                if nlmsg_type == libc::NLMSG_DONE as u16 {
                    debug!(
                        "Received NLMSG_DONE, finished checking {} rules",
                        proto_name
                    );
                    return Ok(found);
                }

                // Check for NLMSG_ERROR
                if nlmsg_type == libc::NLMSG_ERROR as u16 {
                    debug!("Received NLMSG_ERROR");
                    // Update remaining length and move to next message
                    remaining -= nlmsg_align(nlmsg_len) as i32;
                    nlh = nlmsg_next(nlh);
                    continue;
                }

                // NFT_MSG_NEWRULE = ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)
                let nft_msg_newrule =
                    ((libc::NFNL_SUBSYS_NFTABLES << 8) | libc::NFT_MSG_NEWRULE) as u16;
                if nlmsg_type == nft_msg_newrule {
                    debug!(
                        "Found NFT_MSG_NEWRULE, checking for our {} marker",
                        proto_name
                    );

                    let rule_ptr = sys::nftnl_rule_alloc();
                    if rule_ptr.is_null() {
                        debug!("Failed to allocate nftnl_rule");
                        remaining -= nlmsg_align(nlmsg_len) as i32;
                        nlh = nlmsg_next(nlh);
                        continue;
                    }

                    // Parse the netlink message into the rule structure
                    if sys::nftnl_rule_nlmsg_parse(nlh, rule_ptr) < 0 {
                        debug!("Failed to parse rule message");
                        sys::nftnl_rule_free(rule_ptr);
                        remaining -= nlmsg_align(nlmsg_len) as i32;
                        nlh = nlmsg_next(nlh);
                        continue;
                    }

                    // Get userdata from the rule
                    let mut userdata_len: u32 = 0;
                    let userdata_ptr = sys::nftnl_rule_get_data(
                        rule_ptr,
                        sys::NFTNL_RULE_USERDATA as u16,
                        &mut userdata_len as *mut u32,
                    );

                    if !userdata_ptr.is_null() && userdata_len == marker.len() as u32 {
                        let userdata_slice = std::slice::from_raw_parts(
                            userdata_ptr as *const u8,
                            userdata_len as usize,
                        );
                        trace!(
                            "Found userdata (len={}): {:?}, looking for: {:?}",
                            userdata_len,
                            std::str::from_utf8(userdata_slice).unwrap_or("?"),
                            std::str::from_utf8(marker).unwrap_or("?")
                        );
                        if userdata_slice == marker {
                            debug!("Found existing {} rule with our marker!", proto_name);
                            found = true;
                        } else {
                            debug!("Found userdata but it doesn't match our marker");
                        }
                    } else {
                        trace!(
                            "No userdata found in this rule (ptr null={}, len={})",
                            userdata_ptr.is_null(),
                            userdata_len
                        );
                    }

                    sys::nftnl_rule_free(rule_ptr);
                }

                // Update remaining length and move to next message
                remaining -= nlmsg_align(nlmsg_len) as i32;
                nlh = nlmsg_next(nlh);
            }
        }
    }
}

unsafe fn set_rule_userdata(rule: &Rule, marker: &[u8]) {
    // alas, we need to break the abstraction as Rule.rule is not public
    let rule_as_bytes = rule as *const Rule as *const u8;
    // the rust compiler is swapping the two fields of Rule;
    // *mut sys::nftnl_rule shows up later in memory
    let rule_ptr_ptr = rule_as_bytes.offset(8) as *const *mut sys::nftnl_rule;
    let rule_ptr = *rule_ptr_ptr;

    sys::nftnl_rule_set_data(
        rule_ptr,
        sys::NFTNL_RULE_USERDATA as u16,
        marker.as_ptr() as *const std::os::raw::c_void,
        marker.len() as u32,
    );
}

async fn nat_rule_exists(socket: &mut netlink_sys::TokioSocket) -> anyhow::Result<bool> {
    check_rule_exists(
        socket,
        libc::NFPROTO_IPV4 as u32,
        c"nat",
        c"POSTROUTING",
        TS_NAT_RULE_MARKER,
        "IPv4 NAT",
    )
    .await
}

async fn nat6_rule_exists(socket: &mut netlink_sys::TokioSocket) -> anyhow::Result<bool> {
    check_rule_exists(
        socket,
        libc::NFPROTO_IPV6 as u32,
        c"nat",
        c"POSTROUTING",
        TS_NAT6_RULE_MARKER,
        "IPv6 NAT",
    )
    .await
}

async fn create_nat6_rule() -> anyhow::Result<()> {
    info!("Creating IPv6 NAT rule for fc00::/64 subnet");

    let mut socket = create_netfilter_socket()?;

    // First, ensure the nat table and POSTROUTING chain exist
    ensure_nat_table_and_chain_for_family(&mut socket, ProtoFamily::Ipv6).await?;

    // Check if our rule already exists
    if nat6_rule_exists(&mut socket).await? {
        info!("IPv6 NAT rule already exists, skipping creation");
        return Ok(());
    }

    // Create the NAT rule
    let table = Table::new(&c"nat", ProtoFamily::Ipv6);
    let chain = Chain::new(&c"POSTROUTING", &table);
    let mut rule = Rule::new(&chain);

    debug!("Building IPv6 NAT rule for POSTROUTING chain");

    // Load nfproto metadata (check if IPv6)
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));

    // Load source IPv6 address
    rule.add_expr(&nft_expr!(payload ipv6 saddr));

    // Apply bitwise mask for fc00::/64 network
    // Network mask: ffff:ffff:ffff:ffff:0:0:0:0 (64-bit prefix)
    let network_mask: [u8; 16] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let zero_xor: [u8; 16] = [0u8; 16];
    rule.add_expr(&nft_expr!(bitwise mask &network_mask[..], xor &zero_xor[..]));

    // Compare with network address fc00::
    let network_addr: [u8; 16] = [
        0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    rule.add_expr(&nft_expr!(cmp == &network_addr[..]));

    // Add a counter
    rule.add_expr(&nft_expr!(counter));

    debug!("About to add XtTarget expression for IPv6");
    rule.add_expr(&XtTarget::masquerade_v6());
    debug!("XtTarget expression added for IPv6");

    debug!("Adding user data marker to IPv6 NAT rule");
    unsafe {
        set_rule_userdata(&rule, TS_NAT6_RULE_MARKER);
    }

    debug!("Sending IPv6 NAT rule to netfilter");
    send_rule(&mut socket, &rule).await?;

    info!("IPv6 NAT rule created successfully");
    Ok(())
}

async fn create_nat_rule() -> anyhow::Result<()> {
    info!("Creating NAT rule for 172.31.0.0/30 subnet");

    let mut socket = create_netfilter_socket()?;

    // First, ensure the nat table and POSTROUTING chain exist
    ensure_nat_table_and_chain_for_family(&mut socket, ProtoFamily::Ipv4).await?;

    // Check if our rule already exists
    if nat_rule_exists(&mut socket).await? {
        info!("NAT rule already exists, skipping creation");
        return Ok(());
    }

    // Create the NAT rule
    let table = Table::new(&c"nat", ProtoFamily::Ipv4);
    let chain = Chain::new(&c"POSTROUTING", &table);
    let mut rule = Rule::new(&chain);

    debug!("Building NAT rule for POSTROUTING chain");

    // Load nfproto metadata (check if IPv4)
    rule.add_expr(&nft_expr!(meta nfproto));
    rule.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));

    // Load source IP address
    rule.add_expr(&nft_expr!(payload ipv4 saddr));

    // Apply bitwise mask for 172.31.0.0/30 network
    // Network mask: 255.255.255.252 (30-bit prefix)
    let network_mask = 0xfffffffcu32.to_be_bytes();
    let zero_xor: &[u8] = &[0u8, 0u8, 0u8, 0u8];
    rule.add_expr(&nft_expr!(bitwise mask &network_mask[..], xor zero_xor));

    // Compare with network address 172.31.0.0
    let network_addr = Ipv4Addr::new(172, 31, 0, 0).octets();
    rule.add_expr(&nft_expr!(cmp == &network_addr[..]));

    // Add a counter
    rule.add_expr(&nft_expr!(counter));

    // Add masquerade action using xt target for iptables compatibility
    debug!("About to add XtTarget expression");
    rule.add_expr(&XtTarget::masquerade());
    debug!("XtTarget expression added");
    // alternative not compatible with iptables:
    // rule.add_expr(&nftnl::expr::Masquerade);

    // Add our unique marker as userdata to identify this rule later
    debug!("Adding user data marker to NAT rule");
    unsafe {
        set_rule_userdata(&rule, TS_NAT_RULE_MARKER);
    }

    debug!("Sending NAT rule to netfilter");
    send_rule(&mut socket, &rule).await?;

    info!("NAT rule created successfully");
    Ok(())
}

async fn ensure_nat_table_and_chain_for_family(
    socket: &mut netlink_sys::TokioSocket,
    family: ProtoFamily,
) -> anyhow::Result<()> {
    let family_name = match family {
        ProtoFamily::Ipv4 => "IPv4",
        ProtoFamily::Ipv6 => "IPv6",
        _ => "unknown",
    };
    info!(
        "Ensuring {} nat table and POSTROUTING chain exist",
        family_name
    );

    let mut batch = Batch::new();
    let table = Table::new(&c"nat", family);
    let mut chain = Chain::new(&c"POSTROUTING", &table);
    chain.set_hook(nftnl::Hook::PostRouting, 100); // NF_INET_POST_ROUTING = 4, priority = 100 (NF_IP_PRI_NAT_SRC)
    chain.set_policy(nftnl::Policy::Accept);
    chain.set_type(nftnl::ChainType::Nat);
    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&chain, nftnl::MsgType::Add);
    let finalized_batch = batch.finalize();

    let kernel_addr = SocketAddr::new(0, 0);
    let bytes_sent = socket
        .sendmsg(&finalized_batch, &kernel_addr)
        .await
        .context(format!(
            "Failed to send {} table/chain creation batch",
            family_name
        ))?;

    debug!("Sent {} bytes", bytes_sent);
    info!("{} table and chain creation batch sent", family_name);
    Ok(())
}

async fn send_rule<'a>(
    socket: &mut netlink_sys::TokioSocket,
    rule: &'a Rule<'a>,
) -> anyhow::Result<()> {
    debug!("Sending NAT rule to netfilter");

    let mut batch = Batch::new();
    batch.add(rule, nftnl::MsgType::Add);
    let finalized_batch = batch.finalize();

    let kernel_addr = SocketAddr::new(0, 0);
    let bytes_sent = socket
        .sendmsg(&finalized_batch, &kernel_addr)
        .await
        .context("Failed to send batch to netfilter")?;

    debug!("Sent {} bytes", bytes_sent);

    // The kernel doesn't send ACKs for successful batched operations (no NLM_F_ACK flag?),
    // but it DOES send NLMSG_ERROR immediately if there's a problem. Check for errors
    // with a short timeout to catch any immediate failures.
    let timeout_duration = std::time::Duration::from_millis(100);
    match tokio::time::timeout(timeout_duration, socket.recv_from_full()).await {
        Ok(Ok((recv_buffer, _addr))) => {
            debug!(
                "Received response from kernel ({} bytes)",
                recv_buffer.len()
            );

            // check if it's an error
            unsafe {
                let nlh = recv_buffer.as_ptr() as *const libc::nlmsghdr;
                let remaining = recv_buffer.len() as i32;

                if nlmsg_ok(nlh, remaining) {
                    let nlmsg_type = (*nlh).nlmsg_type;

                    if nlmsg_type == libc::NLMSG_ERROR as u16 {
                        let err_msg = (nlh as *const u8).add(std::mem::size_of::<libc::nlmsghdr>())
                            as *const libc::nlmsgerr;
                        let error_code = (*err_msg).error;

                        if error_code != 0 {
                            error!("Kernel rejected NAT rule with error code: {}", error_code);
                            anyhow::bail!(
                                "Kernel rejected NAT rule: {} ({})",
                                std::io::Error::from_raw_os_error(-error_code),
                                error_code
                            );
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => {
            anyhow::bail!("Failed to receive response from kernel: {}", e);
        }
        Err(_) => {
            // Timeout is expected - no error means success
            debug!("No error response from kernel (success)");
        }
    }

    info!("NAT rule batch sent successfully");
    Ok(())
}

fn enable_interface_forwarding(interface: &str) -> anyhow::Result<()> {
    // Enable IPv4 forwarding on the specific interface
    let ipv4_path = format!("/proc/sys/net/ipv4/conf/{}/forwarding", interface);
    let mut f =
        File::create(&ipv4_path).with_context(|| format!("Failed to open {}", ipv4_path))?;
    f.write_all(b"1")
        .context("Failed to enable IPv4 forwarding")?;
    info!("IPv4 forwarding enabled on {} interface", interface);

    // Enable IPv6 forwarding on the specific interface
    let ipv6_path = format!("/proc/sys/net/ipv6/conf/{}/forwarding", interface);
    let mut f =
        File::create(&ipv6_path).with_context(|| format!("Failed to open {}", ipv6_path))?;
    f.write_all(b"1")
        .context("Failed to enable IPv6 forwarding")?;
    info!("IPv6 forwarding enabled on {} interface", interface);

    Ok(())
}

async fn ensure_filter_table_and_chain(
    socket: &mut netlink_sys::TokioSocket,
    family: ProtoFamily,
) -> anyhow::Result<()> {
    let family_name = match family {
        ProtoFamily::Ipv4 => "IPv4",
        ProtoFamily::Ipv6 => "IPv6",
        _ => "unknown",
    };
    info!(
        "Ensuring {} filter table and FORWARD chain exist",
        family_name
    );

    let mut batch = Batch::new();
    let table = Table::new(&c"filter", family);
    let mut chain = Chain::new(&c"FORWARD", &table);
    chain.set_hook(nftnl::Hook::Forward, 0);
    chain.set_policy(nftnl::Policy::Accept);
    chain.set_type(nftnl::ChainType::Filter);
    batch.add(&table, nftnl::MsgType::Add);
    batch.add(&chain, nftnl::MsgType::Add);
    let finalized_batch = batch.finalize();

    let kernel_addr = SocketAddr::new(0, 0);
    let bytes_sent = socket
        .sendmsg(&finalized_batch, &kernel_addr)
        .await
        .context("Failed to send filter table/chain creation batch")?;

    debug!("Sent {} bytes", bytes_sent);
    info!("{} filter table and chain creation batch sent", family_name);
    Ok(())
}

async fn create_forward_rules(interface: &str) -> anyhow::Result<()> {
    let mut socket = create_netfilter_socket()?;

    ensure_filter_table_and_chain(&mut socket, ProtoFamily::Ipv4).await?;
    ensure_filter_table_and_chain(&mut socket, ProtoFamily::Ipv6).await?;

    create_forward_rules_for_family(&mut socket, ProtoFamily::Ipv4, interface).await?;
    create_forward_rules_for_family(&mut socket, ProtoFamily::Ipv6, interface).await?;

    info!("FORWARD rules created successfully for {}", interface);
    Ok(())
}

async fn create_forward_rules_for_family(
    socket: &mut netlink_sys::TokioSocket,
    family: ProtoFamily,
    interface: &str,
) -> anyhow::Result<()> {
    let (family_name, proto_family, out_marker, in_marker) = match family {
        ProtoFamily::Ipv4 => (
            "IPv4",
            libc::NFPROTO_IPV4 as u32,
            TS_FORWARD_OUT_RULE_MARKER,
            TS_FORWARD_IN_RULE_MARKER,
        ),
        ProtoFamily::Ipv6 => (
            "IPv6",
            libc::NFPROTO_IPV6 as u32,
            TS_FORWARD6_OUT_RULE_MARKER,
            TS_FORWARD6_IN_RULE_MARKER,
        ),
        _ => anyhow::bail!("Unsupported protocol family"),
    };

    let c_interface = CString::new(interface).unwrap();

    info!("Creating {} FORWARD rules for {}", family_name, interface);

    let table = Table::new(&c"filter", family);
    let chain = Chain::new(&c"FORWARD", &table);

    // Rule 1: Accept packets from interface (outbound from namespace)
    let out_exists = check_rule_exists(
        socket,
        proto_family,
        c"filter",
        c"FORWARD",
        out_marker,
        &format!("{} FORWARD out", family_name),
    )
    .await?;

    if !out_exists {
        let mut rule_out = Rule::new(&chain);
        rule_out.add_expr(&nft_expr!(meta iifname));
        rule_out.add_expr(&nft_expr!(cmp == c_interface.as_bytes_with_nul()));
        rule_out.add_expr(&nft_expr!(counter));
        rule_out.add_expr(&nft_expr!(verdict accept));

        // Add marker to rule 1
        debug!(
            "Setting {} FORWARD out marker: {:?}",
            family_name,
            std::str::from_utf8(out_marker).unwrap_or("?")
        );
        unsafe {
            set_rule_userdata(&rule_out, out_marker);
        }

        send_rule(socket, &rule_out).await?;
        info!("{} FORWARD out rule created", family_name);
    } else {
        info!("{} FORWARD out rule already exists", family_name);
    }

    // Rule 2: Accept RELATED,ESTABLISHED packets to interface (return traffic)
    let in_exists = check_rule_exists(
        socket,
        proto_family,
        c"filter",
        c"FORWARD",
        in_marker,
        &format!("{} FORWARD in", family_name),
    )
    .await?;

    if !in_exists {
        // Use xt_match for iptables compatibility
        let mut rule_in = Rule::new(&chain);
        rule_in.add_expr(&nft_expr!(meta oifname));
        rule_in.add_expr(&nft_expr!(cmp == c_interface.as_bytes_with_nul()));
        rule_in.add_expr(&XtConntrack3::conntrack_state_established_related());
        rule_in.add_expr(&nft_expr!(counter));
        rule_in.add_expr(&nft_expr!(verdict accept));

        // Add marker to rule 2
        debug!(
            "Setting {} FORWARD in marker: {:?}",
            family_name,
            std::str::from_utf8(in_marker).unwrap_or("?")
        );
        unsafe {
            set_rule_userdata(&rule_in, in_marker);
        }

        send_rule(socket, &rule_in).await?;
        info!("{} FORWARD in rule created", family_name);
    } else {
        info!("{} FORWARD in rule already exists", family_name);
    }

    info!("{} FORWARD rules created for {}", family_name, interface);
    Ok(())
}

pub async fn setup_interfaces() -> anyhow::Result<()> {
    info!("Setting up network interfaces for Tailscale in isolated namespace");

    debug!("Creating namespaces");
    let namespaces = create_namespace()?;

    debug!("Establishing rtnetlink connection");
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    debug!("Rtnetlink connection established");

    info!("Setting up veth interface pair");
    create_veth_pair(&handle, &namespaces.net).await?;

    info!("Adding default route in namespace");
    enter_ns(&namespaces.net, async {
        debug!("Establishing rtnetlink connection inside namespace");
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        debug!("Rtnetlink connection established inside namespace");

        let veth_ns_idx = ifname_to_index(&handle, VETH_NAME_NS).await?;
        debug!(
            "Index of {} inside namespace: {}",
            VETH_NAME_NS, veth_ns_idx
        );

        bring_up_interface(&handle, veth_ns_idx).await?;
        configure_veth_ns(&handle, veth_ns_idx).await?;
        add_default_route(&handle).await?;
        Ok(())
    })
    .await?;

    info!("Setting up NAT for namespace traffic");
    create_nat_rule().await?;
    create_nat6_rule().await?;

    info!("Enabling forwarding on {} interface", VETH_NAME_HOST);
    enable_interface_forwarding(VETH_NAME_HOST)?;

    info!("Creating FORWARD rules for {} interface", VETH_NAME_HOST);
    create_forward_rules(VETH_NAME_HOST).await?;

    info!("Network interfaces setup completed successfully");
    Ok(())
}
