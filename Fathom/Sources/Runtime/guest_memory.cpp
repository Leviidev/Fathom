#include "guest_memory.h"

#include "fathom_log.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace fathom {
namespace {

int ToHostProtection(int guest_protection) {
    // Deliberately drops kGuestProtExec -- see guest_memory.h's header comment. A guest
    // page marked executable is mapped host-readable and FEXCore compiles from it.
    int host = 0;
    if ((guest_protection & kGuestProtRead) != 0) {
        host |= PROT_READ;
    }
    if ((guest_protection & kGuestProtWrite) != 0) {
        host |= PROT_WRITE;
    }
    return host == 0 ? PROT_NONE : host;
}

} // namespace

GuestAddressSpace::GuestAddressSpace(uint64_t base, uint64_t size, uint64_t page_size)
    : base_ {base}
    , size_ {size}
    , page_size_ {page_size} {
    free_.push_back(Extent {base, size});
}

GuestAddressSpace::~GuestAddressSpace() {
    for (const auto& mapping : external_) {
        if (munmap(reinterpret_cast<void*>(mapping.begin), mapping.size) != 0) {
            FATHOM_WARN("external mapping munmap at %#llx failed: %s",
                        static_cast<unsigned long long>(mapping.begin), std::strerror(errno));
        }
    }
    if (base_ != 0 && munmap(reinterpret_cast<void*>(base_), size_) != 0) {
        FATHOM_WARN("guest arena munmap failed: %s", std::strerror(errno));
    }
}

bool GuestAddressSpace::AdoptExternalMapping(uint64_t address, uint64_t size, int protection) {
    if (size == 0) {
        return false;
    }
    std::scoped_lock lock {mutex_};
    external_.push_back(Extent {address, size});
    RecordCommitted(address, size, protection);
    return true;
}

GuestAddressSpace* GuestAddressSpace::Reserve(uint64_t size, std::string& error) {
    const auto page_size = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    const uint64_t aligned = (size + page_size - 1) & ~(page_size - 1);

    // PROT_NONE keeps this a pure address-space reservation: nothing is dirtied, so it
    // does not count against the process's memory limit until a range is committed.
    void* address = mmap(nullptr, aligned, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) {
        error = std::string {"could not reserve a "} + std::to_string(aligned >> 20) +
                "MB guest address space: " + std::strerror(errno);
        return nullptr;
    }

    FATHOM_INFO("reserved guest arena: %llu MB at %p (host page size %llu)",
                static_cast<unsigned long long>(aligned >> 20), address,
                static_cast<unsigned long long>(page_size));
    return new GuestAddressSpace {reinterpret_cast<uint64_t>(address), aligned, page_size};
}

bool GuestAddressSpace::TakeFreeExtent(uint64_t address, uint64_t size) {
    const uint64_t end = address + size;
    for (size_t index = 0; index < free_.size(); ++index) {
        auto& extent = free_[index];
        if (address < extent.begin || end > extent.end()) {
            continue;
        }

        const uint64_t head = address - extent.begin;
        const uint64_t tail = extent.end() - end;
        if (head == 0 && tail == 0) {
            free_.erase(free_.begin() + static_cast<long>(index));
        } else if (head == 0) {
            extent.begin = end;
            extent.size = tail;
        } else if (tail == 0) {
            extent.size = head;
        } else {
            const Extent remainder {end, tail};
            extent.size = head;
            free_.insert(free_.begin() + static_cast<long>(index) + 1, remainder);
        }
        return true;
    }
    return false;
}

void GuestAddressSpace::ReturnFreeExtent(uint64_t address, uint64_t size) {
    Extent freed {address, size};
    auto position = std::lower_bound(free_.begin(), free_.end(), freed,
                                     [](const Extent& lhs, const Extent& rhs) { return lhs.begin < rhs.begin; });
    position = free_.insert(position, freed);

    // Coalesce with the neighbour on each side so a long-running guest that mmaps and
    // munmaps repeatedly does not shred the arena into unusable slivers.
    if (position + 1 != free_.end() && position->end() == (position + 1)->begin) {
        position->size += (position + 1)->size;
        free_.erase(position + 1);
    }
    if (position != free_.begin() && (position - 1)->end() == position->begin) {
        (position - 1)->size += position->size;
        free_.erase(position);
    }
}

void GuestAddressSpace::RecordCommitted(uint64_t address, uint64_t size, int protection) {
    GuestRange range {address, size, protection};
    auto position = std::lower_bound(committed_.begin(), committed_.end(), range,
                                     [](const GuestRange& lhs, const GuestRange& rhs) { return lhs.begin < rhs.begin; });
    committed_.insert(position, range);
}

uint64_t GuestAddressSpace::Allocate(uint64_t size, uint64_t hint, int protection) {
    if (size == 0) {
        return 0;
    }

    std::scoped_lock lock {mutex_};
    const uint64_t length = AlignUp(size);

    if (hint != 0) {
        const uint64_t aligned_hint = AlignDown(hint);
        if (aligned_hint >= base_ && aligned_hint + length <= base_ + size_ &&
            TakeFreeExtent(aligned_hint, length)) {
            if (mprotect(reinterpret_cast<void*>(aligned_hint), length, ToHostProtection(protection)) != 0) {
                FATHOM_WARN("commit at hint %#llx failed: %s",
                            static_cast<unsigned long long>(aligned_hint), std::strerror(errno));
                ReturnFreeExtent(aligned_hint, length);
                return 0;
            }
            RecordCommitted(aligned_hint, length, protection);
            return aligned_hint;
        }
    }

    // First fit. The arena is large and guest allocation patterns are not adversarial,
    // so the extra bookkeeping of best fit is not worth it here.
    for (const auto& extent : free_) {
        if (extent.size < length) {
            continue;
        }
        const uint64_t address = extent.begin;
        if (!TakeFreeExtent(address, length)) {
            continue;
        }
        if (mprotect(reinterpret_cast<void*>(address), length, ToHostProtection(protection)) != 0) {
            FATHOM_WARN("commit of %llu bytes failed: %s", static_cast<unsigned long long>(length),
                        std::strerror(errno));
            ReturnFreeExtent(address, length);
            return 0;
        }
        RecordCommitted(address, length, protection);
        return address;
    }

    FATHOM_WARN("guest arena exhausted: no free extent for %llu bytes",
                static_cast<unsigned long long>(length));
    return 0;
}

bool GuestAddressSpace::CommitFixed(uint64_t address, uint64_t size, int protection) {
    if (size == 0) {
        return false;
    }

    std::scoped_lock lock {mutex_};
    const uint64_t begin = AlignDown(address);
    const uint64_t end = AlignUp(address + size);
    if (begin < base_ || end > base_ + size_) {
        return false;
    }
    if (!TakeFreeExtent(begin, end - begin)) {
        // Already committed. Widening the protection is the only sane interpretation --
        // ELF segments routinely share a host page with the segment before them.
        return Protect(begin, end - begin, protection);
    }
    if (mprotect(reinterpret_cast<void*>(begin), end - begin, ToHostProtection(protection)) != 0) {
        FATHOM_ERROR("fixed commit at %#llx (%llu bytes) failed: %s",
                     static_cast<unsigned long long>(begin),
                     static_cast<unsigned long long>(end - begin), std::strerror(errno));
        ReturnFreeExtent(begin, end - begin);
        return false;
    }
    RecordCommitted(begin, end - begin, protection);
    return true;
}

bool GuestAddressSpace::Release(uint64_t address, uint64_t size) {
    if (size == 0) {
        return false;
    }

    std::scoped_lock lock {mutex_};
    const uint64_t begin = AlignDown(address);
    const uint64_t end = AlignUp(address + size);
    if (begin < base_ || end > base_ + size_) {
        return false;
    }

    // Drop the physical pages but keep the reservation: the arena has to stay one
    // contiguous mapping, so this is mprotect+madvise rather than munmap.
    if (mprotect(reinterpret_cast<void*>(begin), end - begin, PROT_NONE) != 0) {
        FATHOM_WARN("release protect at %#llx failed: %s", static_cast<unsigned long long>(begin),
                    std::strerror(errno));
    }
    madvise(reinterpret_cast<void*>(begin), end - begin, MADV_FREE);

    std::vector<GuestRange> survivors;
    survivors.reserve(committed_.size());
    for (const auto& range : committed_) {
        if (range.end() <= begin || range.begin >= end) {
            survivors.push_back(range);
            continue;
        }
        if (range.begin < begin) {
            survivors.push_back(GuestRange {range.begin, begin - range.begin, range.protection});
        }
        if (range.end() > end) {
            survivors.push_back(GuestRange {end, range.end() - end, range.protection});
        }
    }
    committed_ = std::move(survivors);
    ReturnFreeExtent(begin, end - begin);
    return true;
}

bool GuestAddressSpace::Protect(uint64_t address, uint64_t size, int protection) {
    const uint64_t begin = AlignDown(address);
    const uint64_t end = AlignUp(address + size);

    // The guest's pages are 4KB and this device's are 16KB, so a guest range rarely lands
    // on a host page boundary. Rounding outward and applying the new protection to the
    // whole of it would take access away from up to three neighbouring guest pages that
    // were never mentioned -- which is exactly what happens when a dynamic loader marks
    // its relocated data read-only and quietly strips write access from the start of the
    // segment that follows.
    //
    // Only host pages lying wholly inside the request get the protection as asked. The
    // partial pages at either end keep whatever they already allowed, widened by the new
    // protection, because a page shared by two guest pages has to satisfy both.
    const uint64_t strict_begin = AlignUp(address);
    const uint64_t strict_end = AlignDown(address + size);
    const auto protection_for = [&](uint64_t range_begin, uint64_t range_end, int existing) {
        const bool wholly_inside = range_begin >= strict_begin && range_end <= strict_end;
        return wholly_inside ? protection : (existing | protection);
    };

    std::vector<GuestRange> updated;
    updated.reserve(committed_.size() + 2);
    bool touched = false;
    for (const auto& range : committed_) {
        if (range.end() <= begin || range.begin >= end) {
            updated.push_back(range);
            continue;
        }
        touched = true;
        if (range.begin < begin) {
            updated.push_back(GuestRange {range.begin, begin - range.begin, range.protection});
        }
        const uint64_t overlap_begin = std::max(range.begin, begin);
        const uint64_t overlap_end = std::min(range.end(), end);
        updated.push_back(GuestRange {overlap_begin, overlap_end - overlap_begin,
                                      protection_for(overlap_begin, overlap_end, range.protection)});
        if (range.end() > end) {
            updated.push_back(GuestRange {end, range.end() - end, range.protection});
        }
    }
    if (!touched) {
        return false;
    }

    std::sort(updated.begin(), updated.end(),
              [](const GuestRange& lhs, const GuestRange& rhs) { return lhs.begin < rhs.begin; });
    committed_ = std::move(updated);

    // The host mapping keeps read/write regardless; only the guest's view changes.
    // A guest mprotect that *adds* write access still needs the host to allow it.
    if ((protection & kGuestProtWrite) != 0) {
        mprotect(reinterpret_cast<void*>(begin), end - begin, PROT_READ | PROT_WRITE);
    }
    return true;
}

bool GuestAddressSpace::Contains(uint64_t address, uint64_t size) const {
    return address >= base_ && size <= size_ && address + size <= base_ + size_;
}

bool GuestAddressSpace::Validate(uint64_t address, uint64_t size, int required) const {
    if (size == 0) {
        return true;
    }
    if (address > UINT64_MAX - size) {
        return false;
    }

    std::scoped_lock lock {mutex_};
    uint64_t cursor = address;
    const uint64_t end = address + size;
    for (const auto& range : committed_) {
        if (range.end() <= cursor) {
            continue;
        }
        if (range.begin > cursor) {
            return false; // Hole.
        }
        if ((range.protection & required) != required) {
            return false;
        }
        cursor = range.end();
        if (cursor >= end) {
            return true;
        }
    }
    return false;
}

bool GuestAddressSpace::RangeFor(uint64_t address, GuestRange* out) const {
    std::scoped_lock lock {mutex_};
    for (const auto& range : committed_) {
        if (address >= range.begin && address < range.end()) {
            if (out != nullptr) {
                *out = range;
            }
            return true;
        }
    }
    return false;
}

std::vector<GuestRange> GuestAddressSpace::Snapshot() const {
    std::scoped_lock lock {mutex_};
    return committed_;
}

uint64_t GuestAddressSpace::CommittedBytes() const {
    std::scoped_lock lock {mutex_};
    uint64_t total = 0;
    for (const auto& range : committed_) {
        total += range.size;
    }
    return total;
}

} // namespace fathom
