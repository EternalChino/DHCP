# DHCP

A custom TCP/IP network stack and DHCP client built for the **TM4C123GXL** LaunchPad with an **ENC28J60** Ethernet controller, developed for CSE4352 (IoT and Networking), Spring 2026.

The project implements Ethernet, ARP, IP, ICMP, UDP, and a full DHCP client from scratch (RFC 2131), on top of a bare-metal driver layer (SPI, UART, GPIO, timers, EEPROM), with a UART command-line interface for configuration.

## Hardware

- **MCU:** TM4C123GH6PM (TM4C123GXL LaunchPad)
- **Ethernet controller:** ENC28J60 (SPI)
- **System clock:** 40 MHz
- **Interface:** UART0 @ 115200 baud

## Features

- **Ethernet / ARP / IP / ICMP / UDP** — frame and packet handling, ARP request/response, IP datagram routing, ICMP echo (ping) response
- **DHCP client** (RFC 2131) — full state machine covering:
  - Discover → Offer → Request → ACK
  - ARP-based address conflict detection before accepting an offered address
  - Lease renewal (T1) and rebinding (T2) timers
  - Release and refresh on demand
- **Persistent configuration** — IP, subnet mask, gateway, DNS, and DHCP mode are stored in EEPROM and restored on power-up
- **Timer service** — general-purpose callback-based timers used for DHCP lease/ARP-window timing
- **MQTT client** — connect/disconnect, publish, subscribe, unsubscribe
- **UART command-line interface** for live configuration and diagnostics

## CLI Commands

| Command | Description |
|---|---|
| `ip` | Display current IP address, DHCP mode, subnet mask, gateway, and DNS |
| `set ip \| sn \| gw \| dns \| time \| mqtt w.x.y.z` | Set IP, subnet mask, gateway, DNS, time server, or MQTT broker address (persisted to EEPROM) |
| `dhcp on \| off` | Enable/disable DHCP mode (persisted to EEPROM) |
| `dhcp renew \| release` | Renew or release the current DHCP lease |
| `ping w.x.y.z` | Ping an IP address |
| `mqtt connect \| disconnect` | Connect/disconnect from the configured MQTT broker |
| `mqtt publish TOPIC DATA` | Publish a message to a topic |
| `mqtt subscribe \| unsubscribe TOPIC` | Subscribe/unsubscribe to a topic |
| `reboot` | Restart the microcontroller |
| `help` | List available commands |

## Power-Up Behavior

On boot, the device initializes the system clock, UART, timer service, and Ethernet controller, then reads the last-saved configuration from EEPROM. If DHCP mode was enabled, a new DHCP discovery process starts immediately (the lease itself is not persisted across power cycles — only the DHCP on/off setting and static fallback addresses are).

## Project Structure

```
├── ethernet.c/h    # Main loop, CLI, Ethernet frame handling
├── arp.c/h         # ARP request/response
├── ip.c/h          # IP datagram handling
├── icmp.c/h        # ICMP (ping)
├── udp.c/h         # UDP datagram handling
├── tcp.c/h         # TCP (partial)
├── dhcp.c/h        # DHCP client state machine
├── mqtt.c/h        # MQTT client
├── socket.c/h      # Socket abstraction
├── eth0.c/h        # ENC28J60 driver
├── spi0.c/h        # SPI driver
├── uart0.c/h       # UART driver
├── gpio.c/h        # GPIO driver
├── timer.c/h       # Timer service
├── eeprom.c/h      # EEPROM read/write
├── clock.c/h       # System clock configuration
└── wait.c/h        # Blocking delay utilities
```

## Author

**Angel Montalvo**
CSE4352 — IoT and Networking, Spring 2026

The base driver framework (Ethernet, SPI, UART, GPIO, timer, EEPROM, clock) was provided by the course instructor, Jason Losh, per course policy. The DHCP client, CLI extensions, and MQTT client were implemented as part of this assignment.
