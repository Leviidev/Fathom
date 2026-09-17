// fathom_api.h -- the entire surface Swift sees of Fathom's emulator core.
//
// Everything below is plain C so it can be pulled straight into Swift through the
// bridging header. The C++ side (fex_engine, elf_loader, guest_memory,
// linux_syscalls) never leaks across this boundary.
//
// Threading: a session is created, run and destroyed on one thread -- the run is
// blocking and the caller is expected to own a background thread for it.
// fathom_session_request_stop and fathom_session_status are the two exceptions and
// are safe to call from any thread while a run is in flight.

#ifndef FATHOM_API_H
#define FATHOM_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Build/runtime capability
// ---------------------------------------------------------------------------

/// False when the app was linked without FEXCore (no emulator core available).
/// Every other call in this header is a no-op returning failure in that case.
bool fathom_runtime_available(void);

/// Upstream FEX commit this core was built from. Never NULL.
const char* fathom_runtime_fex_revision(void);

/// Host page size, which on Apple Silicon is 16384 and *not* the guest's 4096.
/// Exposed because it explains a lot of the loader's alignment behaviour.
size_t fathom_host_page_size(void);

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

typedef enum {
    FATHOM_LOG_DEBUG = 0,
    FATHOM_LOG_INFO = 1,
    FATHOM_LOG_WARN = 2,
    FATHOM_LOG_ERROR = 3,
} fathom_log_level;

typedef void (*fathom_log_sink)(void* context, fathom_log_level level, const char* message);

/// Installs the sink every core-side log line is delivered to. Pass NULL to detach.
/// The sink may be called from any thread, including from inside a guest syscall.
void fathom_set_log_sink(fathom_log_sink sink, void* context);

/// Minimum level that reaches the sink. Defaults to FATHOM_LOG_INFO.
void fathom_set_log_level(fathom_log_level level);

/// Installs fatal-signal handlers that append a final diagnostic record to the file at
/// `log_path` before the process dies: which signal, the fault address, and the last
/// guest syscall serviced. Without this a hard fault inside the JIT just ends the
/// process and the log stops mid-line with no indication of why.
void fathom_install_crash_handler(const char* log_path);

// ---------------------------------------------------------------------------
// Program inspection
// ---------------------------------------------------------------------------

typedef enum {
    FATHOM_PROGRAM_UNKNOWN = 0,
    FATHOM_PROGRAM_STATIC = 1,      ///< ET_EXEC, no PT_INTERP: fixed load address.
    FATHOM_PROGRAM_STATIC_PIE = 2,  ///< ET_DYN, no PT_INTERP: loadable anywhere.
    FATHOM_PROGRAM_DYNAMIC = 3,     ///< PT_INTERP present: needs a guest root filesystem.
} fathom_program_kind;

typedef struct {
    bool ok;                  ///< False means `error` explains why this file is unusable.
    fathom_program_kind kind;
    bool loadable;            ///< False for a program this device cannot host (see `error`).
    uint64_t entry;           ///< e_entry, before any PIE relocation.
    uint64_t image_size;      ///< Span of all PT_LOAD segments, in bytes.
    uint64_t min_vaddr;       ///< Lowest PT_LOAD p_vaddr (0 for PIE).
    char machine[32];         ///< e.g. "x86-64".
    char interpreter[256];    ///< PT_INTERP contents, or "".
    char error[256];
} fathom_program_info;

/// Reads the ELF headers of `path` without mapping or running anything.
bool fathom_inspect_program(const char* path, fathom_program_info* out_info);

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

typedef struct fathom_session fathom_session;

typedef struct {
    const char* program_path;      ///< Host path of the guest executable.
    const char* const* argv;       ///< Guest argv; argv[0] defaults to program_path.
    int argc;
    const char* const* envp;       ///< Guest environment, "KEY=VALUE" strings.
    int envc;
    const char* guest_root;        ///< Host directory presented to the guest as "/".
    const char* work_dir;          ///< Guest-absolute starting directory, or NULL for "/".

    uint64_t address_space_size;   ///< Guest arena reservation. 0 picks a default.
    uint64_t stack_size;           ///< Guest stack. 0 picks a default.

    // FEXCore knobs, surfaced in Settings.
    uint32_t max_inst_per_block;   ///< 0 keeps FEXCore's default.
    bool multiblock;
    bool tso_enabled;              ///< Emulate x86's stronger memory ordering.
    bool reduced_precision_x87;
    bool disable_avx;               ///< Tell the guest's CPUID there is no AVX.
    bool trace_syscalls;           ///< Log every guest syscall (very loud).
} fathom_session_config;

/// Fills `config` with the defaults Settings starts from.
void fathom_session_config_defaults(fathom_session_config* config);

typedef enum {
    FATHOM_STATE_IDLE = 0,
    FATHOM_STATE_LOADING = 1,
    FATHOM_STATE_RUNNING = 2,
    FATHOM_STATE_EXITED = 3,
    FATHOM_STATE_FAULTED = 4,
    FATHOM_STATE_STOPPED = 5,  ///< Halted early by fathom_session_request_stop.
} fathom_session_state;

typedef struct {
    fathom_session_state state;
    int exit_code;
    uint64_t rip;
    uint64_t rsp;
    uint64_t syscall_count;
    uint64_t instructions_hint;  ///< Guest blocks entered; a progress signal, not a count.
    char message[256];           ///< Fault/exit detail, or "".
} fathom_session_status;

/// Guest writes to fd 1 and 2 arrive here. `bytes` is not NUL-terminated.
typedef void (*fathom_output_sink)(void* context, int fd, const char* bytes, size_t length);

/// Creates a session and loads the program into a fresh guest address space.
/// Returns NULL on failure, writing a human-readable reason into `error`.
fathom_session* fathom_session_create(const fathom_session_config* config, char* error, size_t error_size);

void fathom_session_set_output_sink(fathom_session* session, fathom_output_sink sink, void* context);

/// Delivers keystrokes to the guest's standard input.
///
/// Bytes, not characters: an arrow key is the three-byte escape sequence a terminal
/// would send (ESC [ A and friends), which is exactly what a program reading a terminal
/// expects to find. Safe to call from any thread while the guest is running.
void fathom_session_send_input(fathom_session* session, const char* bytes, size_t length);

/// Says no more input will ever arrive. A guest reading standard input gets end-of-file
/// instead of waiting for a key that is never coming.
void fathom_session_close_input(fathom_session* session);

/// The guest's display, if it has opened one.
typedef struct {
    bool active;          ///< False until the guest opens /dev/fb0.
    uint32_t width;
    uint32_t height;
    uint32_t stride;      ///< Bytes per row.
    uint32_t bits_per_pixel;
    const void* pixels;   ///< Guest memory. Valid while the session lives.
    uint64_t writes;      ///< Counts guest frames presented, for a "is it drawing" check.
} fathom_framebuffer;

/// Describes the guest's framebuffer. Returns false when it has not opened one.
///
/// The pixels are guest memory read directly -- there is no copy and no handshake, which
/// is exactly how a real framebuffer device behaves: the program writes pixels and they
/// are on screen.
bool fathom_session_framebuffer(fathom_session* session, fathom_framebuffer* out);

/// True once the guest has put its terminal into raw mode, which is what a program does
/// when it wants individual keypresses rather than whole lines. The UI uses this to know
/// an on-screen keypad is worth showing.
bool fathom_session_wants_keys(fathom_session* session);

/// Runs the guest until it exits, faults, or is stopped. Blocking.
/// Returns the guest's exit code, or -1 if it did not exit normally.
int fathom_session_run(fathom_session* session);

/// Asks the guest to stop at the next syscall boundary. Safe from any thread.
void fathom_session_request_stop(fathom_session* session);

/// Safe from any thread, including during a run.
void fathom_session_get_status(fathom_session* session, fathom_session_status* out_status);

void fathom_session_destroy(fathom_session* session);

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

typedef struct {
    bool jit_available;          ///< A JIT-capable mapping was obtained successfully.
    bool debugger_attached;      ///< csops/entitlement says this process may codesign dynamically.
    bool has_dynamic_codesigning;
    uint64_t largest_reservation; ///< Largest contiguous VA reservation obtained, in bytes.
    uint64_t lowest_mappable;    ///< Lowest address the kernel let us map. See note below.
    char detail[512];
} fathom_diagnostics;

/// Probes what this device actually permits: JIT, address-space reservation size, and
/// how low in the address space a mapping can be placed.
///
/// That last one decides which guest programs can run at all. An iOS arm64 binary
/// reserves the first 4GB as __PAGEZERO, so a non-PIE guest wanting its usual
/// 0x400000 load address has nowhere to go, while PIE guests are placed wherever the
/// kernel allows. This probe reports the real number from the real device rather
/// than assuming it.
void fathom_probe_device(fathom_diagnostics* out_diagnostics);

#ifdef __cplusplus
}
#endif

#endif // FATHOM_API_H
