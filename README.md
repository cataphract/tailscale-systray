# Tailscale Systray

A system tray application ([StatusNotifierItem](SNI)) for managing Tailscale VPN
connections on Linux systems.

## Features

- Quick access to Tailscale status from the system tray
- Connect/disconnect to Tailscale with a single click
- View online peers and copy their IPs to the clipboard
- Configure and use exit nodes
- Advertise your device as an exit node
- Authentication via browser for easy login

## Installation

### Prerequisites

- Tailscale CLI installed
- A Linux desktop environment with StatusNotifierItem support

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
tailscale-systray --install
```

Alternatively:

```bash
cargo install tailscale-systray
~/.cargo/bin/tailscale-systray --install
```

## Usage

### Command-line Arguments

```
Usage: tailscale-systray [OPTIONS]

Options:
      --tailscale-bin <TAILSCALE_BIN>
          Tailscale executable [default: tailscale]
      --install
          Locally install icons and desktop file
      --socket <SOCKET>
          Path to tailscaled socket
      --up-arg <UP_ARG>
          Extra arguments to pass "tailscale up"
      --refresh-period <REFRESH_PERIOD>
          Refresh period in seconds [default: 5]
  -v, --verbosity <VERBOSITY>
          Verbosity level (0-5, where 0=error, 1=warn, 2=info, 3=debug, 4=trace, 5=trace+) [default: 2]
  -h, --help
          Print help
```

### System Tray Features

- **Left-click**: Opens the menu
- **Status indicator**:
  - Green checkmark: Tailscale is up and connected
  - Blue globe: Connected through an exit node
  - Red X: Tailscale is down or not connected
- **Menu options**:
  - Enable/Disable Tailscale
  - View online peers (click to copy IP)
  - Configure exit nodes
  - Advertise as an exit node

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- [Tailscale](https://tailscale.com/) for their excellent VPN service
- [KSNI](https://crates.io/crates/ksni) for the StatusNotifierItem implementation


[SNI]: https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/
