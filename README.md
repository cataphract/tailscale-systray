# Tailscale Systray

A system tray application ([StatusNotifierItem][SNI]) for managing Tailscale VPN
connections on Linux systems.

## Features

- Quick access to Tailscale status from the system tray
- Connect/disconnect to Tailscale with a single click
- View online peers and copy their IPs to the clipboard
- Configure and use exit nodes
- Advertise your device as an exit node
- **Network namespace isolation**: Run tailscaled in an isolated network
  namespace. Exit nodes can be used by only a set of processes.

## Installation

### Prerequisites

- Tailscale CLI installed
- A Linux desktop environment with StatusNotifierItem support

### Pre-built binaries

Binaries are available in [GitHub releases][releases].

### From Source

```bash
# Clone the repository
git clone https://github.com/cataphact/tailscale-systray.git
cd tailscale-systray

# Build the application
cargo build --release

# Copy the binary somewhere
sudo cp target/release/tailscale-systray /usr/local/bin/

# Copy icons/.desktop files for current user (invoke the *copied* executable!)
tailscale-systray install
```

Alternatively:

```bash
cargo install tailscale-systray
~/.cargo/bin/tailscale-systray install
```

Some native libraries (libmnl, libnftnl) are required.

## Usage

### Command-line Arguments

```
Application Indicator (SNI) for Tailscale

Usage: tailscale-systray [OPTIONS] [COMMAND]

Commands:
  run         Run the application normally
  install     Install icons and desktop file
  ns-prepare  Prepare segregated networking
  ns-helper   Launch namespace fd supplier
  ns-enter    Enter the namespaces for the segregated network and execute
  systemd     Systemd integration commands
  help        Print this message or the help of the given subcommand(s)

Options:
  -v, --verbosity <VERBOSITY>  Verbosity level (0-5, where 0=error, 1=warn, 2=info, 3=debug, 4=trace, 5=trace+) [default: 2]
  -h, --help                   Print help
  -V, --version                Print version
```

### System Tray Features

- **Left-click**: Opens the menu
- **Status indicator**:
  - Green checkmark: Tailscale is up and connected
  - Blue globe: Connected through an exit node
  - Red X: Tailscale is down or not connected
  - Red circumference around to signal running in separate namespace
- **Menu options**:
  - Enable/Disable Tailscale
  - View online peers (click to copy IP)
  - Configure exit nodes
  - Advertise as an exit node
  - Allow LAN access
  - Enable/disable namespace isolation (systemd only)
  - Run command in namespace

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- [Tailscale](https://tailscale.com/) for their excellent VPN service
- [KSNI](https://crates.io/crates/ksni) for the StatusNotifierItem implementation


[SNI]: https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/
[releases]: https://github.com/cataphract/tailscale-systray/releases
