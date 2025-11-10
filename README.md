# Echoes - Network Packet Sniffer

> *"Let the voice of love take you higher!"* 🎵

A lightweight, high-performance packet sniffer written in C for Linux systems. Echoes captures and analyzes network traffic at the link layer, providing detailed insights into Ethernet, IP, TCP, and UDP packets.

*Inspired by Koichi Hirose's Stand from JoJo's Bizarre Adventure: Diamond is Unbreakable - just like Echoes evolved through three acts, this tool captures and reverberates network packets with precision.*

## Features

- 🔍 **Raw Packet Capture** - Captures packets at the link layer using AF_PACKET sockets
- 🎯 **Advanced Filtering** - Filter by protocol, IP addresses, ports, and network interfaces
- 📊 **Detailed Packet Analysis** - Displays Ethernet, IP, TCP/UDP headers and payload data
- 💾 **Logging** - Saves captured packets to a customizable log file
- 🚀 **Zero Dependencies** - Uses only standard Linux libraries
- 🎭 **Three Acts of Analysis** - Like Echoes ACT 1, 2, and 3, progressively reveals packet structure from MAC to payload

## Requirements

- **Operating System:** Linux (kernel 2.2+)
- **Compiler:** GCC or any C99-compatible compiler
- **Privileges:** Root access (required for raw socket operations)

## Installation

### Clone the Repository
```bash
git clone https://github.com/niorsentinel/echoes.git
cd echoes
```

### Compile
```bash
gcc -o echoes echoes.c -Wall -Wextra -O2
```

Or use the provided Makefile:
```bash
make
```

## Usage

### Basic Syntax
```bash
sudo ./echoes [OPTIONS]
```

### Command-Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-t` | `--TCP` | Filter TCP packets only |
| `-u` | `--UDP` | Filter UDP packets only |
| `-s IP` | `--sip IP` | Filter by source IP address |
| `-d IP` | `--dip IP` | Filter by destination IP address |
| `-p PORT` | `--sport PORT` | Filter by source port |
| `-o PORT` | `--dport PORT` | Filter by destination port |
| `-i IFACE` | `--sif IFACE` | Filter by source network interface |
| `-g IFACE` | `--dif IFACE` | Filter by destination network interface |
| `-f PATH` | `--logfile PATH` | Specify custom log file path |

### Examples

**Capture all traffic:**
```bash
sudo ./echoes
```

**Capture only TCP traffic:**
```bash
sudo ./echoes -t
```

**Capture DNS queries (UDP port 53):**
```bash
sudo ./echoes -u --dport 53
```

**Capture HTTP traffic from specific IP:**
```bash
sudo ./echoes -t --sip 192.168.1.100 --dport 80
```

**Capture traffic on specific interface:**
```bash
sudo ./echoes --sif eth0
```

**Save to custom log file:**
```bash
sudo ./echoes -f /var/log/my_capture.log
```

**Complex filtering:**
```bash
sudo ./echoes -t --sip 10.0.0.5 --dport 443 -f https_traffic.log
```

## Output Format

Echoes logs captured packets in a human-readable format:

```
================ Echoes Vibration =================

[Echoes Act 1] MAC Resonance Initiated:
   Source MAC → AA-BB-CC-DD-EE-FF
   Destination MAC → 11-22-33-44-55-66
   Protocol Energy → 0x0800

[Echoes Act 2] IP Waves Detected:
   Source IP → 192.168.1.100
   Destination IP → 93.184.216.34
   Protocol Type → 6 | TTL → 64

[Echoes Act 3] TCP Pulse!
   Source Port → 45678
   Destination Port → 443
   Sequence → 123456789 | ACK → 987654321
   Flags [SYN:0 ACK:1 PSH:1 FIN:0 RST:0]

[Echoes] Data Resonance → 
17 03 03 00 50 AB CD EF 12 34 56 78 90 AB CD EF
...

================= Echoes End ======================
```

## How It Works

1. **Raw Socket Creation** - Creates an `AF_PACKET` socket to capture all network traffic
2. **Packet Reception** - Receives raw packets from the network interface
3. **Header Parsing** - Extracts and parses Ethernet, IP, TCP/UDP headers
4. **Filtering** - Applies user-defined filters to match specific traffic
5. **Logging** - Writes matching packets to the log file in real-time

## Architecture

```
┌─────────────────┐
│  Network Layer  │
└────────┬────────┘
         │
    ┌────▼─────┐
    │ AF_PACKET│
    │  Socket  │
    └────┬─────┘
         │
    ┌────▼─────────┐
    │   echoes     │
    │   Filter     │
    └────┬─────────┘
         │
    ┌────▼─────────┐
    │  Log File    │
    └──────────────┘
```

## Security Considerations

⚠️ **WARNING:** This tool requires root privileges and captures all network traffic. Use responsibly and only on networks you own or have permission to monitor.

- Always run with `sudo` for raw socket access
- Be aware of legal implications of packet sniffing
- Never use on networks without authorization
- Sensitive data may be captured in packet payloads

## Troubleshooting

### Permission Denied
```bash
# Solution: Run with sudo
sudo ./echoes
```

### No Packets Captured
- Check if you have active network traffic
- Verify the network interface is up: `ip link show`
- Try without filters first to ensure basic functionality

### Interface Not Found
```bash
# List available interfaces
ip link show
# or
ifconfig
```

## Technical Details

- **Language:** C (C99 standard)
- **Socket Type:** `AF_PACKET` with `SOCK_RAW`
- **Buffer Size:** 65536 bytes (maximum Ethernet frame size)
- **Thread Safety:** Single-threaded, uses `inet_ntop()` for safe IP conversion

## Limitations

- Linux-only (uses Linux-specific packet socket API)
- Single-threaded capture
- No support for packet injection
- Limited to Ethernet networks
- Does not decrypt encrypted traffic

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by tcpdump and Wireshark
- Built using Linux packet socket API
- Named after Echoes (Reverb), Koichi Hirose's Stand from JoJo's Bizarre Adventure Part 4: Diamond is Unbreakable
- Thanks to the open-source community

---

*"S-H-I-T!"* - Echoes ACT 3

## Author

Ash <3

Project Link: [https://github.com/niorsentinel/echoes](https://github.com/niorsentinel/echoes)

## Disclaimer
This tool is provided for educational and authorized network monitoring purposes only. The authors are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before monitoring network traffic.

⭐ If you find this project useful, please consider giving it a star!

---

**⭐ If you find this project useful, please consider giving it a star!**
