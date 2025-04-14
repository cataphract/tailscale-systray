# Changelog

All notable changes to tailscale-systray will be documented in this file.

## [0.2.0] - 2025-10-14

### Added

- **Network namespace isolation**: Major new feature allowing tailscaled to run in an isolated network namespace
  - Created `namespaces.rs` module for network namespace management
  - Implemented virtual ethernet (veth) interface pair creation and configuration
  - Added NAT rule creation using nftables for traffic routing between namespace and host
  - Automatic IPv4 forwarding enablement (no IPv6 support yet)
  - Custom DNS configuration within the namespace
- **Systemd integration**: Tools for managing tailscaled with namespace isolation
  - `ns-prepare` command to set up isolated network namespace
  - `ns-install` command to create systemd drop-in configuration
  - `ns-uninstall` command to remove namespace configuration
  - Automatic detection of tailscaled.service presence
  - PID tracking to ensure namespace helper stays synchronized with tailscaled
- **Namespace launcher**: Helper process system for executing commands in isolated namespace
  - `ns-helper` command that runs with elevated privileges
  - Unix socket-based IPC for secure communication
  - File descriptor passing support for launching applications
  - Privilege dropping after namespace setup
  - Credential verification for security
- **New icons**: Added namespace-specific status icons
  - `tailscale-exit-node-ns.svg` for exit node status in namespace mode
  - `tailscale-up-ns.svg` for active status in namespace mode
- Added support for `--exit-node-allow-lan-access` flag when configuring exit nodes

### Changed

- Updated dependencies:
  - Added `netlink-sys` 0.8.7 with tokio support
  - Added `nftnl` 0.7.0 for nftables manipulation
  - Added `rtnetlink` 0.18.1 for network interface management

### Fixed

- **Tailscale API compatibility**: Updated JSON deserialization to handle changes in Tailscale's status output
  - Removed `roles` field from `User` and `UserProfile` structs (no longer returned by Tailscale)
  - Added `default` attribute to `profile_pic_url` to handle missing profile pictures
  - Added support for new optional fields: `cert_domains`, `client_version`, `peer_relay`, `taildrop_target`, `no_file_sharing_reason`, `key_expiry`
  - Added `Default` trait derivations to `TailscalePrefs`, `AutoUpdate`, and `AppConnector` for better handling of missing fields

### Technical Details

- Network namespace lives at `/var/run/tailscale-net/ns/net`
- Mount namespace lives at `/var/run/tailscale-net/ns/mnt`
- Veth interfaces use addresses in the 172.31.0.0/30 subnet
- NAT rules are tagged with unique marker for easy tracking
- Helper process uses abstract Unix sockets for IPC

## [0.1.0] - 2025-04-14

### Added

- Initial release
- System tray application (StatusNotifierItem) for Tailscale on Linux
- Quick connect/disconnect functionality
- View online peers with IP address copying
- Exit node configuration and management
- Ability to advertise device as exit node
- Browser-based authentication flow
- Desktop file and icon installation (`--install` flag)

### Dependencies

- `ksni` 0.3 for StatusNotifierItem support
- `notify-rust` 4.11 for desktop notifications
- `arboard` 3.4 for clipboard operations
- `tokio` 1.44 for async runtime
- `serde` and `serde_json` for configuration
- `rust-embed` 8.6.0 for embedded resources
- `anyhow` 1.0 for error handling
- `clap` 4.5 for CLI argument parsing
- `env_logger` 0.11 and `log` 0.4 for logging
- `users` 0.11 for user management

[0.2.0]: https://github.com/cataphact/tailscale-systray/compare/v0.2.0
[0.1.0]: https://github.com/cataphact/tailscale-systray/releases/tag/v0.1.0
