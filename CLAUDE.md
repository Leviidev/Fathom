# Fathom

An iOS x86-64 PC emulator: FEXCore's JIT, a Linux syscall layer, and a SwiftUI front end.

## Ground rules

- Commit messages are simple one-liners that say what changed ("added settings tab").
  No co-author trailer on this project.
- Shipping means both: `.ipa` on the Desktop, and commits pushed to
  `github.com/Leviidev/Fathom`.
- The Xcode project and `Fathom/Libs/*.a` are generated. Never hand-edit the pbxproj —
  change `scripts/generate_project.rb` and regenerate.

## Build

```bash
./scripts/build-fexcore-ios.sh   # FEXCore for arm64 iOS -> Fathom/Libs
ruby scripts/generate_project.rb # -> Fathom/Fathom.xcodeproj
./scripts/check-runtime.sh       # compile + link the C++ core only (fast iteration)
./scripts/build-ipa.sh           # -> ~/Desktop/Fathom.ipa
```

## Things that will bite

- **`DEBUG=1` cannot be defined for the C++ sources.** FEXCore's `LogManager.h` declares
  an enumerator named `DEBUG`. `generate_project.rb` sets
  `GCC_PREPROCESSOR_DEFINITIONS` without `$(inherited)` for this reason.
- **`__clear_cache` must be provided by the app** (`Sources/Runtime/darwin_support.cpp`).
  FEXCore's JIT calls it and Apple's device compiler-rt does not define it, so leaving it
  out fails at link time with an error pointing into FEXCore.
- **BreakpointJIT.framework must be copied, never linked.** Linking it puts it in
  `LC_LOAD_DYLIB`, and AMFI kills a sideloaded app that embeds an entitled framework
  before `main()`. FEXCore `dlopen`s it lazily instead.
- **The host page size is 16KB, the guest's is 4KB.** Never assume 4096 anywhere in the
  runtime; `sysconf(_SC_PAGESIZE)` is the host's.
- **Guest memory is never mapped `PROT_EXEC`.** FEXCore reads guest code as data and
  emits ARM64 for it; only FEXCore's own code buffers need JIT permission.
- **Exiting the guest is a `longjmp`.** `SYSCALL` is not a block-ending instruction on
  non-Windows, so `exit_group` cannot stop the guest by rewriting RIP. `fex_engine.cpp`
  uses `FEXCore::UncheckedLongJump`, the same mechanism FEX's own thread exit uses.
- **Linux is not Darwin.** `errno` values, `O_*` flags, and `struct stat` all differ.
  `linux_syscalls.cpp` translates every one of them by hand; do not pass a guest flag
  word or host struct straight through.
