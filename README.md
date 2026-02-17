# cctraceroute

A traceroute implementation in modern C++23. Traces the network path to a destination by sending UDP probes with incrementing TTL values and analyzing ICMP responses.

Built as a solution to the [Coding Challenges traceroute challenge](https://codingchallenges.fyi/challenges/challenge-traceroute/).

## Example

```
$ sudo ./build/bin/cctraceroute dns.google.com
traceroute to dns.google.com (8.8.4.4), 64 hops max, 32 byte packets
 1  my-router.local (192.168.68.1) 5.131 ms
 2  broadband (192.168.1.1) 4.999 ms
 3  *  * *
 4  63.130.172.45 (63.130.172.45) 30.561 ms
 5  dns.google (8.8.4.4) 28.342 ms
```

## Building

### Prerequisites

- C++23 compatible compiler (GCC 13+ or Clang 17+)
- CMake 3.16+

### Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Run tests

```bash
cmake --build build --target test
```

## Usage

```
sudo ./build/bin/cctraceroute <hostname> [options]
```

Root privileges (or `CAP_NET_RAW`) are required because cctraceroute opens a raw ICMP socket.

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --maxhops` | Maximum number of hops | `64` |
| `-w, --timeout` | Probe timeout in milliseconds | `100` |
| `-q, --queries` | Number of probes per hop | `3` |
| `-t, --text` | Payload message text | `codingchallenges.fyi trace route` |
| `-h, --help` | Print help | |

### Examples

```bash
# Basic trace
sudo ./build/bin/cctraceroute google.com

# Limit to 20 hops with 500ms timeout
sudo ./build/bin/cctraceroute google.com -m 20 -w 500

# Single probe per hop
sudo ./build/bin/cctraceroute google.com -q 1
```

## How it works

For each TTL (1, 2, 3, ...):

1. Send UDP packets to the destination on incrementing high ports (starting at 33434)
2. An intermediate router with TTL=0 replies with **ICMP Time Exceeded**
3. The destination itself replies with **ICMP Destination Unreachable** (port unreachable)
4. Measure the round-trip time between send and receive
5. Multiple probes per hop are averaged for a more stable RTT

The ICMP response contains a copy of the original IP+UDP headers, which lets us match replies back to specific probes via the destination port.

## Project structure

```
bin/           CLI entry point
lib/           Header-only library
  icmp.hpp       ICMP packet parsing (uses libc structs)
  prober.hpp     UDP sender + ICMP receiver with RTT measurement
  traceroute.hpp Orchestration and output formatting
  dns.hpp        DNS forward/reverse resolution
test/
  unit/          Unit tests (ICMP parsing, traceroute logic)
  integration/   Integration tests (DNS resolution)
```
