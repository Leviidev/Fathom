# Where this is up to

Last updated at the end of the session that added guest input, the terminal, and the
framebuffer device.

## The goal being worked on

**Video output.** The target is a graphical 2048 drawing real pixels, in colour, on the
device. The earlier framing of this as "SDL support" was too narrow -- what is actually
wanted is graphics output in general. SDL is one possible client of that, not the point.

## Done and shipped

- x86-64 ELF loading, guest address space, Linux syscall layer, FEXCore JIT integration.
- Guest keyboard input: a real blocking `read` on fd 0, `TCSETS` raw mode, `O_NONBLOCK`.
- A VT100 terminal emulator and an on-screen keypad, shown once the guest goes raw.
- Two terminal games (`testprograms/tictactoe`, `testprograms/play2048`), both working
  on device. Released as v1.0.0.

## Done but not yet visible: the framebuffer device

`linux_syscalls.cpp` implements `/dev/fb0` and it compiles, links, and is committed.
The guest can already:

- `open("/dev/fb0")` -- answered directly, with a virtual fd numbered from 900 so it
  cannot collide with a real descriptor.
- `ioctl(FBIOGET_VSCREENINFO)` / `ioctl(FBIOGET_FSCREENINFO)` -- geometry, written field
  by field at the offsets x86-64 Linux uses.
- `mmap` it -- and this returns **the framebuffer itself, not a copy**, which is the
  whole point: what the guest writes is what should appear.

The display is **480x800, 32bpp, BGRA** (blue at byte 0), allocated from the guest arena.
`fathom_session_framebuffer()` exposes it to Swift.

## Next, in order

1. **The SwiftUI side.** Nothing renders the framebuffer yet -- this is the only reason
   there is still no picture. Poll `fathom_session_framebuffer`, build a `CGImage` over
   the BGRA bytes (`byteOrder32Little | noneSkipFirst`), and draw it. `EmulatorSession`'s
   status timer runs at 10Hz; raise it to 30Hz while a display is active. Show the
   display instead of the terminal when the framebuffer is live, keeping the keypad.

2. **A graphical 2048** (`testprograms/fb2048.c`) drawing straight to the mapped
   framebuffer: the classic tile palette, a small bitmap font for the numbers, arrow keys
   read the same way the terminal games read them. This is the deliverable that proves
   video works end to end.

3. **Only then consider SDL.** Alpine's *static* SDL2 was verified to contain x11,
   wayland, KMSDRM, offscreen, dummy and evdev, and links cleanly into a `-static-pie`
   binary with just `-lSDL2 -pthread -lm`. But every one of those backends wants a
   display server iOS does not have. The tractable route is a small SDL2 video backend
   over `/dev/fb0` -- SDL2's own `dummy` driver is the right shape to copy and is about
   80 lines. Not needed for the goal above.

## Environment notes that cost time to learn

- **`docker` here is Colima, not Docker Desktop** (`~/.colima`, ~5 GB). Do not delete it
  thinking it is redundant. Its VM disk is sparse, so a full host disk corrupts the
  containerd store from inside the VM and even `rm` starts returning I/O errors. The fix
  is stopping docker in the VM, clearing `/var/lib/docker` and `/var/lib/containerd`, and
  `colima restart`.
- Guest binaries are cross-compiled in an `--platform linux/amd64` Alpine container, and
  **Docker can only see paths under `/Users`** -- building from a scratch directory in
  `/tmp` silently fails with "No such file or directory".
- `/System/Volumes/Preboot` holding tens of GB means a staged macOS update is sitting
  uninstalled (`cryptex1/current` plus `cryptex1/proposed`). Installing the update is the
  only safe way to reclaim it; nothing under Preboot may be deleted by hand.
