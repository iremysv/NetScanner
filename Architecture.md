# NetScanner Architecture

## Overview
NetScanner uses a modular architecture for packet sniffing, Nmap integration, and traffic analysis.

## Core Modules
- `core/`: Configuration, logging, and base classes.
- `modules/packet_engine/`: PCAP reading and live sniffing using Scapy.
- `modules/nmap_integration/`: Port scanning and vulnerability checks using python-nmap.
- `reports/`: Generation of TXT and JSON reports.
