# AdGuard QUIC Resolver

**Version:** 1.0

AdGuard QUIC Resolver is a Windows DNS forwarder that supports **DoH (DNS over HTTPS)** and **DoQ (DNS over QUIC)**. It provides a lightweight web UI for configuration, logging, and toggleable features like running at Windows startup.  

## Features

- Supports **DoH** and **DoQ**, with optional DoQ preference.
- Runs as a **console-less Windows application**.
- Provides a **web-based dashboard** at `http://localhost:8080/`:
  - Configure DoH and DoQ upstream servers.
  - Toggle preferences and startup option.
  - View logs in real time.
- Modern UI with **dark/OLED mode**.
- Automatically detects primary IPv4 address.
- Lightweight and minimal dependencies:
  - [miekg/dns](https://github.com/miekg/dns)
  - [quic-go](https://github.com/quic-go/quic-go)
  - [golang.org/x/sys/windows/registry](https://pkg.go.dev/golang.org/x/sys/windows/registry)

## Installation

### Build from source (requires Go 1.20+)

Clone the repository:

```bash
git clone https://github.com/jwdali1/AdGuard-QUIC-Resolver.git
cd "AdGuard-QUIC-Resolver"
```

Build for Windows (AMD64):

```powershell
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-H=windowsgui -s -w -X main.version=v1" -o AdGuardQUICResolver_amd64.exe
```

Build for Windows (ARM64):

```powershell
set GOOS=windows
set GOARCH=arm64
go build -ldflags "-H=windowsgui -s -w -X main.version=v1" -o AdGuardQUICResolver_arm64.exe
```

> The `-H=windowsgui` flag hides the console window.  

## Usage

1. Run the executable (`.exe`).
2. Open your browser at [http://localhost:8080/](http://localhost:8080/).
3. Configure your upstream DoH/DoQ servers.
4. Toggle preferences and save.
5. Logs are displayed live in the web dashboard.

### Notes

- By default, it listens on **port 53**, which requires administrator privileges.
- If you enable **Run at Windows startup**, the app will automatically start when you log in.
- Logs are limited to the **most recent 1000 entries**.

## File Structure

```
├── main.go               # Main Go source
├── go.mod                # Go module file
├── go.sum                # Dependencies checksum
├── webpage/
│   └── dashboard.html    # Embedded web UI
├── .gitignore            # Ignored files (exe, logs, temp files)
└── README.md             # Project documentation
```

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

## Contributing

Feel free to submit pull requests or open issues.  

- Keep the web UI in `webpage/dashboard.html`.
- Ensure any changes to DNS logic are thoroughly tested.
- Keep release versions consistent with semantic versioning.

## Release

Version 1.0 includes:

- Both AMD64 and ARM64 Windows executables.
- Modern web UI with darkmode.
- Configurable DoH/DoQ upstreams.
- Startup toggle and logs.

