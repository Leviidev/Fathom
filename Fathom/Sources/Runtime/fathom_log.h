// fathom_log.h -- one logging path for the whole core.
//
// Everything funnels through the sink Swift installs (FathomLog, which mirrors to an
// exportable file in the app container) so a crash report from a device is readable
// without Xcode attached.
#pragma once

#include "fathom_api.h"

namespace fathom {

void Log(fathom_log_level level, const char* format, ...) __attribute__((format(printf, 2, 3)));

/// True when `level` would actually reach the sink. Worth checking before building an
/// expensive message -- the syscall tracer logs on a very hot path.
bool LogEnabled(fathom_log_level level);

} // namespace fathom

#define FATHOM_DEBUG(...) ::fathom::Log(FATHOM_LOG_DEBUG, __VA_ARGS__)
#define FATHOM_INFO(...) ::fathom::Log(FATHOM_LOG_INFO, __VA_ARGS__)
#define FATHOM_WARN(...) ::fathom::Log(FATHOM_LOG_WARN, __VA_ARGS__)
#define FATHOM_ERROR(...) ::fathom::Log(FATHOM_LOG_ERROR, __VA_ARGS__)
