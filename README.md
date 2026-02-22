Network Analyzer (simple) using Python sockets

This repository includes a lightweight network analyzer/port scanner implemented in Python using the standard `socket` module.

Files
- network_analyzer.py — scanner script

Usage

Scan a single host (default ports 1-1024):

```bash
python d:/GTECH/network_analyzer.py 192.168.1.10
```

Scan specific ports:

```bash
python d:/GTECH/network_analyzer.py 192.168.1.10 -p 22,80,443
```

Scan a CIDR subnet (will iterate hosts):

```bash
python d:/GTECH/network_analyzer.py 192.168.1.0/28 -p 22-1024
```

Adjust timeouts and concurrency:

```bash
python d:/GTECH/network_analyzer.py 10.0.0.5 -p 1-500 -t 0.8 --per-host-workers 40
```

New features (nmap-like):

- Version detection: `-sV` will attempt simple banner/service probes and extract server/version strings.
- JSON output: `-oJ out.json` writes machine-readable results; use `-oJ -` to print JSON to stdout.
- Verbose: `-v` prints extra progress information.

Notes
- This is a learning tool and is not a replacement for nmap. Use it only on systems/networks you own or are authorized to test.
- The script uses TCP connect scans and simple banner probing; results may vary by service and network conditions.

License
- Use as you wish for development and learning.
