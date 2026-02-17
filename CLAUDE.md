# C++ Conventions

## Standard
- C++23. Use `std::span`, `std::optional`, `std::string_view`, designated initializers, `enum class`, `constexpr`.
- Prefer `constexpr` and compile-time computation where possible.

## Style
- Classes/Structs: `PascalCase` (`TraceRoute`, `HopResult`)
- Functions/methods: `snake_case` (`send_probe`, `parse_icmp`)
- Variables: `snake_case` (`dest_ip`, `rtt_ms`)
- Private members: `trailing_underscore_` (`fd_`, `timeout_`, `hostname_`)
- Constants: `kPascalCase` for local constexpr (`kMinIpHeaderLen`), system macros stay `UPPER_CASE`
- Enums: `enum class` with `PascalCase` values (`IcmpType::TimeExceeded`)
- Namespaces: `lowercase::nested`

## Formatting
- `.clang-format` based on Google style, `ColumnLimit: 120`.
- `#pragma once` for include guards.
- Include order: system `<>` headers, blank line, project `""` headers.
- Headers: `.hpp`, sources: `.cpp`.

## Architecture
- Header-only library in `lib/` (CMake `INTERFACE` library). Only executables in `bin/`.
- Dependency injection via abstract base classes with `std::unique_ptr`.
- RAII for resource management (sockets, file descriptors). Acquire in constructor, release in destructor.
- Delete copy operations on RAII types: `ClassName(const ClassName&) = delete;`
- Use `override final` on concrete implementations of virtual methods.
- Static factory methods on structs for semantic construction (`HopResult::reached(ip, rtt)`).

## Error Handling
- `std::optional<T>` for recoverable failures (parsing, network receive).
- `std::runtime_error` for unrecoverable failures (socket creation, send failures).
- Graceful fallbacks where appropriate (reverse DNS falls back to raw IP).

## Memory & Performance
- `std::unique_ptr` for exclusive ownership. No naked `new`/`delete`.
- `std::move` for ownership transfer. Pass large objects by `const&`.
- `std::string_view` and `std::span` for non-owning views in function parameters.
- `std::array` for fixed-size buffers. `std::vector` with `reserve` for dynamic.
- Stack-allocate short-lived RAII objects.

## Designated Initializers
- When using designated initializers, initialize ALL fields explicitly to avoid `-Wmissing-designated-field-initializers`.
- Prefer static factory methods over raw designated initializers for repeated patterns.

## Networking
- Use libc structs (`struct iphdr`, `struct icmphdr`, `struct udphdr`) with `reinterpret_cast` for packet parsing.
- `ntohs`/`htons` for network byte order conversion.
- `std::chrono` types for timeouts and RTT measurement. `steady_clock` for elapsed time.

## Testing
- GoogleTest. `TEST(Suite, Case)` or `TEST_F(Fixture, Case)` naming.
- Arrange/Act/Assert pattern.
- Unit tests in `test/unit/`, integration tests in `test/integration/`.
- Manual stub classes implementing abstract interfaces (no Google Mock).
- Use fixtures (`::testing::Test`) for shared setup and helper methods.
- Factory helpers in tests to reduce boilerplate (`make_icmp_packet`, `make_traceroute`).

## Build
- CMake 3.16+. `CMAKE_CXX_STANDARD 23`, `CMAKE_CXX_STANDARD_REQUIRED ON`.
- Compiler flags: `-Wall -Werror -Wextra -Wpedantic`.
- `FetchContent` for external dependencies (googletest, cxxopts).
- `gtest_discover_tests()` for automatic test registration.
