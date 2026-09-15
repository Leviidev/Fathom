#include "guest_console.h"

#include <chrono>

namespace fathom {

void GuestConsole::SetOutputCallback(OutputCallback callback, void* context) {
    std::scoped_lock lock {output_mutex_};
    output_ = callback;
    output_context_ = context;
}

void GuestConsole::Write(int fd, const char* bytes, size_t length) {
    OutputCallback callback = nullptr;
    void* context = nullptr;
    {
        std::scoped_lock lock {output_mutex_};
        callback = output_;
        context = output_context_;
    }
    if (callback != nullptr) {
        callback(context, fd, bytes, length);
    }
}

void GuestConsole::SendInput(const char* bytes, size_t length) {
    if (bytes == nullptr || length == 0) {
        return;
    }
    {
        std::scoped_lock lock {input_mutex_};
        input_.insert(input_.end(), bytes, bytes + length);
    }
    input_ready_.notify_all();
}

int64_t GuestConsole::ReadInput(char* out, size_t max) {
    std::unique_lock lock {input_mutex_};
    while (input_.empty()) {
        if (stop_requested_.load(std::memory_order_relaxed)) {
            return 0;
        }
        if (nonblocking_stdin_.load(std::memory_order_relaxed)) {
            return -1;
        }
        // The timeout exists so a stop request is noticed even if no key ever arrives.
        input_ready_.wait_for(lock, std::chrono::milliseconds(100));
    }

    const size_t available = std::min(max, input_.size());
    for (size_t index = 0; index < available; ++index) {
        out[index] = input_.front();
        input_.pop_front();
    }
    return static_cast<int64_t>(available);
}

bool GuestConsole::InputAvailable() const {
    std::scoped_lock lock {input_mutex_};
    return !input_.empty();
}

void GuestConsole::WaitForInput(int milliseconds) {
    std::unique_lock lock {input_mutex_};
    input_ready_.wait_for(lock, std::chrono::milliseconds(milliseconds));
}

void GuestConsole::SetFramebuffer(const Framebuffer& framebuffer) {
    std::scoped_lock lock {framebuffer_mutex_};
    framebuffer_ = framebuffer;
}

GuestConsole::Framebuffer GuestConsole::Display() const {
    std::scoped_lock lock {framebuffer_mutex_};
    return framebuffer_;
}

void GuestConsole::RequestStop() {
    stop_requested_.store(true, std::memory_order_relaxed);
    // A guest parked in read() is not at a syscall boundary and would otherwise wait for
    // a keystroke that is never coming.
    input_ready_.notify_all();
}

} // namespace fathom
