# Fathom

An x86-64 PC emulator for iOS. Fathom runs x86-64 Linux programs on an iPhone or iPad by
translating them to ARM64 as they execute, using [FEXCore](https://github.com/FEX-Emu/FEX)
— the dynamic recompiler behind FEX-Emu — with a native SwiftUI front end.

## What it does

Import an x86-64 Linux executable, open it, press Run. Fathom maps it into a guest
address space, hands its instructions to FEXCore's JIT, answers its Linux syscalls, and
shows you its output.

The emulator core is genuinely doing the work: FEXCore compiles the guest's x86-64 basic
blocks into ARM64 at runtime, and Fathom supplies the kernel half — an ELF loader, a
guest address space, and a Linux syscall layer covering files, memory, time, and process
basics.

## What runs

| Program shape | Status |
| --- | --- |
| Statically linked, position independent (`-static-pie`) | Runs |
| Statically linked, non-PIE (`-static`) | Loads only if the device permits low fixed mappings — see below |
| Dynamically linked | Not yet: needs a guest root filesystem with the interpreter and libraries |
| 32-bit x86 | No — x86-64 only |

The non-PIE case is a real constraint rather than an oversight. A classic Linux
executable is linked to load at `0x400000`, and an iOS arm64 process reserves the first
4GB of its address space as `__PAGEZERO`, so there is nowhere to put it. Settings →
Device probe measures what your specific device actually allows instead of assuming.

Threads are not implemented: `clone` returns `ENOSYS`, so a guest runs single-threaded.

## JIT

iOS does not let an ordinary app make memory executable, and FEXCore cannot run a single
instruction without that. Fathom gets the permission the way other iOS emulators do — by
having [StikDebug](https://github.com/StikDebug/StikDebug) attach to the process and
service the `BRK` traps FEXCore's allocator issues when it wants an executable region.

Fathom asks for this automatically on launch when it is missing. The app carries
`get-task-allow`, `dynamic-codesigning`, and
`com.apple.developer.kernel.increased-memory-limit`.

## Building

FEXCore is not vendored here: it is built from the tree in AetherCore4 and the resulting
static libraries are copied into `Fathom/Libs`.

```bash
./scripts/build-fexcore-ios.sh   # builds FEXCore for arm64 iOS
ruby scripts/generate_project.rb # writes Fathom/Fathom.xcodeproj
./scripts/build-ipa.sh           # builds and drops Fathom.ipa on the Desktop
```

Set `FEXCORE_SRC` if the FEXCore tree lives somewhere other than
`~/Documents/Coding/AetherCore4/aetherps4-public-release/runtime/sources/fexcore-darwin`.

`scripts/check-runtime.sh` compiles *and links* just the C++ core against the iOS SDK,
which is much faster than a full app build when working on the emulator itself — and the
link half is the part that actually proves the FEXCore integration.

## Trying it

`testprograms/` has a self-test that exercises one part of the emulator per section --
integer and x87 and vector maths through the JIT, `malloc` through `brk` and `mmap`, the
argv/envp/auxv stack the loader builds, the clocks, and reading and writing a file in the
guest root.

There are also two games, because a PC emulator that cannot take input is only half of
one. Both put the terminal into raw mode and read arrow keys as the escape sequences a
real terminal sends:

- **tictactoe** -- arrows move, Enter places, against a full-minimax bot that cannot be
  beaten. The best available result is a draw.
- **play2048** -- arrows slide the board.

```bash
./testprograms/build.sh    # -> ~/Desktop/{fathom-selftest,tictactoe,play2048}
```

Copy them onto the device (AirDrop, or the Files app into Fathom's Programs folder), add
them from the Library tab, and run. The self-test should report PASS on every line; the
games get a terminal and an on-screen keypad, which Fathom shows as soon as the guest
asks for raw mode.

## Layout

```
Fathom/
├── Sources/
│   ├── App/        Entry point, TabView, logging
│   ├── Models/     Library, session, settings, JIT support
│   ├── Views/      Library and Settings tabs, console, diagnostics
│   └── Runtime/    The emulator core (C++)
│       ├── fathom_api.h       Everything Swift sees
│       ├── elf_loader.cpp     x86-64 ELF loading and process-entry stack
│       ├── guest_memory.cpp   Guest address space
│       ├── linux_syscalls.cpp The kernel half
│       └── fex_engine.cpp     The FEXCore embedding
├── Libs/           FEXCore static libraries (built, not committed)
├── Frameworks/     BreakpointJIT.framework
└── Resources/
```

## Licensing

FEXCore is MIT. `Fathom/Frameworks/BreakpointJIT.framework` comes from the StikDebug
project.
