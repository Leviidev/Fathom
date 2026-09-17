#include "guest_memory.h"

#include "fathom_log.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
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
    auto* space = new GuestAddressSpace {reinterpret_cast<uint64_t>(address), aligned, page_size};
    // A way to make a program load where it would load in a busier session. Whether a bug
    // depends on the addresses a program happens to get is otherwise very hard to ask:
    // reproducing it means reproducing everything that ran before it.
    if (const char* skip = getenv("FATHOM_ARENA_SKIP")) {
        const uint64_t bytes = std::strtoull(skip, nullptr, 0);
        if (bytes > 0 && bytes < aligned) {
            space->Allocate(bytes, 0, kGuestProtRead);
            FATHOM_INFO("arena: the first %llu MB are taken, for testing",
                        static_cast<unsigned long long>(bytes >> 20));
        }
    }
    return space;
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

namespace {

/// Returns a range of the arena to the state it was reserved in: unreadable, unwritable,
/// backed by nothing, and able to be made writable again.
///
/// Not mprotect: a guest that mapped a file here left a mapping whose *maximum* protection
/// is whatever the file allowed, and a read-only file leaves a range that can never be
/// made writable again -- so the next program placed there fails to commit, with EACCES, a
/// long way from the mmap that caused it. Only ever used on memory nothing holds any more:
/// mapping over a range also zeroes it, and the guest's 4KB pages share this device's 16KB
/// ones, so doing it to a range that is merely being re-protected would wipe up to three
/// live neighbours -- which reads, much later, as a thread whose stack pointer is zero.
bool MapFreshAnonymous(uint64_t address, uint64_t length) {
    void* placed = mmap(reinterpret_cast<void*>(address), length, PROT_NONE,
                        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return placed != MAP_FAILED && reinterpret_cast<uint64_t>(placed) == address;
}



/// Makes [begin, end) usable at `host_protection`, with anything not already spoken for
/// reading as zero.
///
/// Linux hands out zeroed pages, and a dynamic loader depends on that completely. The
/// arena is reused as processes come and go, so a range handed out again still holds the
/// last owner's bytes unless something clears it -- and mapping over it is how that is
/// done, because it also restores the protection ceiling a mapped file left behind.
///
/// Only over pages nothing else is living in, though. The guest's pages are 4KB and this
/// device's are 16KB, so a span rounded outward to host pages can cover up to three
/// neighbouring guest pages that are still in use; mapping over those wipes them, and it
/// reads much later as a thread whose stack pointer and saved registers are all zero.
bool CommitRange(uint64_t begin, uint64_t end, uint64_t page_size, int host_protection,
                 const std::vector<GuestRange>& committed) {
    uint64_t run_begin = 0;
    uint64_t run_end = 0;
    const auto flush = [&] {
        if (run_end > run_begin) {
            MapFreshAnonymous(run_begin, run_end - run_begin);
        }
        run_begin = run_end = 0;
    };
    for (uint64_t page = begin; page < end; page += page_size) {
        bool occupied = false;
        for (const auto& range : committed) {
            if (range.begin < page + page_size && range.end() > page) {
                occupied = true;
                break;
            }
        }
        if (occupied) {
            flush();
            continue;
        }
        if (run_end != page) {
            flush();
            run_begin = page;
        }
        run_end = page + page_size;
    }
    flush();
    return mprotect(reinterpret_cast<void*>(begin), end - begin, host_protection) == 0;
}

} // namespace

void GuestAddressSpace::ReturnFreeExtent(uint64_t address, uint64_t size) {
    if (size == 0) {
        return;
    }
    for (const auto& extent : free_) {
        if (extent.begin < address + size && address < extent.end()) {
            FATHOM_WARN("arena: %#llx..%#llx is being freed while %#llx..%#llx is already free",
                        static_cast<unsigned long long>(address),
                        static_cast<unsigned long long>(address + size),
                        static_cast<unsigned long long>(extent.begin),
                        static_cast<unsigned long long>(extent.end()));
            return;
        }
    }
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

/// Takes whatever of [begin, end) is still free, without requiring all of it to be.
///
/// TakeFreeExtent is all-or-nothing, which is right for an allocation but wrong for a
/// fixed mapping: a loader reserves a library's whole span and then maps each segment
/// over the top, so the second mapping lands partly on its own memory and partly on free
/// space. Left in the free list, that free part is handed out again later -- to another
/// process -- and two programs end up living at the same address.
void GuestAddressSpace::TakeFreeSpan(uint64_t begin, uint64_t end) {
    for (size_t index = 0; index < free_.size();) {
        auto& extent = free_[index];
        if (extent.end() <= begin || extent.begin >= end) {
            ++index;
            continue;
        }
        const uint64_t head = begin > extent.begin ? begin - extent.begin : 0;
        const uint64_t tail = extent.end() > end ? extent.end() - end : 0;
        if (head == 0 && tail == 0) {
            free_.erase(free_.begin() + static_cast<long>(index));
            continue;
        }
        if (head == 0) {
            extent.begin = end;
            extent.size = tail;
            ++index;
            continue;
        }
        if (tail == 0) {
            extent.size = head;
            ++index;
            continue;
        }
        const Extent remainder {end, tail};
        extent.size = head;
        free_.insert(free_.begin() + static_cast<long>(index) + 1, remainder);
        index += 2;
    }
}

/// The parts of [begin, end) nothing is committed over, host page by host page.
std::vector<std::pair<uint64_t, uint64_t>> GuestAddressSpace::UncommittedIn(uint64_t begin,
                                                                           uint64_t end) const {
    std::vector<std::pair<uint64_t, uint64_t>> gaps;
    uint64_t cursor = begin;
    for (const auto& range : committed_) {
        if (range.end() <= cursor) {
            continue;
        }
        if (range.begin >= end) {
            break;
        }
        if (range.begin > cursor) {
            gaps.emplace_back(cursor, std::min(range.begin, end));
        }
        cursor = std::max(cursor, range.end());
        if (cursor >= end) {
            return gaps;
        }
    }
    if (cursor < end) {
        gaps.emplace_back(cursor, end);
    }
    return gaps;
}

/// Records a committed range, and takes that address away from anything that claimed it
/// before.
///
/// Overlapping entries are not merely untidy. Everything that asks this list a question
/// about an address -- which mapping is here, is it writable, is it still the one a copy
/// was taken from -- gets a different answer depending on which entry it happens to reach
/// first, and a fork's snapshot ends up holding the same page four times over, each with
/// a different idea of when it was mapped. So the newcomer wins, and whatever was there
/// is clipped around it.
void GuestAddressSpace::RecordCommitted(uint64_t address, uint64_t size, int protection) {
    const uint64_t end = address + size;
    std::vector<GuestRange> updated;
    updated.reserve(committed_.size() + 2);
    for (const auto& range : committed_) {
        if (range.end() <= address || range.begin >= end) {
            updated.push_back(range);
            continue;
        }
        // Something was already living here. The arena only hands out what its free list
        // says is free, so this means the free list and this one disagree -- and the
        // program that was here is about to find its memory belongs to somebody else.
        FATHOM_WARN("arena: committing %#llx..%#llx over %#llx..%#llx, which was already "
                    "committed (epoch %llu, prot %d)",
                    static_cast<unsigned long long>(address), static_cast<unsigned long long>(end),
                    static_cast<unsigned long long>(range.begin),
                    static_cast<unsigned long long>(range.end()),
                    static_cast<unsigned long long>(range.epoch), range.protection);
        if (range.begin < address) {
            updated.push_back(GuestRange {range.begin, address - range.begin, range.protection,
                                          range.epoch});
        }
        if (range.end() > end) {
            updated.push_back(GuestRange {end, range.end() - end, range.protection, range.epoch});
        }
    }
    updated.push_back(GuestRange {address, size, protection, next_epoch_++});
    std::sort(updated.begin(), updated.end(),
              [](const GuestRange& lhs, const GuestRange& rhs) { return lhs.begin < rhs.begin; });
    committed_ = std::move(updated);
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
            if (!CommitRange(aligned_hint, aligned_hint + length, page_size_,
                             ToHostProtection(protection), committed_)) {
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
        if (!CommitRange(address, address + length, page_size_,
                         ToHostProtection(protection), committed_)) {
            FATHOM_WARN("commit of %llu bytes at %#llx failed: %s (arena %#llx..%#llx)",
                        static_cast<unsigned long long>(length),
                        static_cast<unsigned long long>(address), std::strerror(errno),
                        static_cast<unsigned long long>(base_),
                        static_cast<unsigned long long>(base_ + size_));
            ReturnFreeExtent(address, length);
            return 0;
        }
        RecordCommitted(address, length, protection);
        return address;
    }

    uint64_t total = 0;
    uint64_t largest = 0;
    for (const auto& extent : free_) {
        total += extent.size;
        largest = std::max(largest, extent.size);
    }
    FATHOM_WARN("guest arena exhausted: no free extent for %llu KB; %llu KB free in %llu "
                "pieces, largest %llu KB",
                static_cast<unsigned long long>(length / 1024),
                static_cast<unsigned long long>(total / 1024),
                static_cast<unsigned long long>(free_.size()),
                static_cast<unsigned long long>(largest / 1024));
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
        // Partly committed already, which is the ordinary case: a loader reserves a
        // library's whole span and then maps each of its segments over the top. The parts
        // that are still free are taken and committed here; the parts that are not keep
        // what they have, widened -- ELF segments routinely share a host page with the
        // segment before them, and taking access away from a neighbour that was never
        // mentioned is how a loader's own data goes read-only underneath it.
        for (const auto& [gap_begin, gap_end] : UncommittedIn(begin, end)) {
            TakeFreeSpan(gap_begin, gap_end);
            if (!CommitRange(gap_begin, gap_end, page_size_, ToHostProtection(protection),
                             committed_)) {
                FATHOM_WARN("fixed commit of the free part at %#llx failed: %s",
                            static_cast<unsigned long long>(gap_begin), std::strerror(errno));
                continue;
            }
            RecordCommitted(gap_begin, gap_end - gap_begin, protection);
        }
        return ProtectLocked(begin, end - begin, protection);
    }
    if (!CommitRange(begin, end, page_size_, ToHostProtection(protection), committed_)) {
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

    std::unique_lock lock {mutex_};
    const uint64_t begin = AlignDown(address);
    const uint64_t end = AlignUp(address + size);
    if (begin < base_ || end > base_ + size_) {
        return false;
    }

    std::vector<GuestRange> survivors;
    survivors.reserve(committed_.size());
    for (const auto& range : committed_) {
        if (range.end() <= begin || range.begin >= end) {
            survivors.push_back(range);
            continue;
        }
        if (range.begin < begin) {
            survivors.push_back(GuestRange {range.begin, begin - range.begin, range.protection, range.epoch});
        }
        if (range.end() > end) {
            survivors.push_back(GuestRange {end, range.end() - end, range.protection, range.epoch});
        }
    }
    // Installed before anything below asks what is still committed -- both the sweep for
    // pages nothing lives in and the decision about what goes back on the free list read
    // this list, and reading it with the range still in it means nothing is ever dropped
    // and the free list ends up holding memory the committed list also holds.
    committed_ = std::move(survivors);

    // Only the host pages nothing else is still living in.
    //
    // The guest's pages are 4KB and the host's are 16KB, so one host page can hold four
    // guest mappings. Protecting the whole rounded span takes a neighbour's memory with
    // it, and the neighbour finds out by faulting on an ordinary store -- a thread stack
    // sharing its last host page with something being freed dies sixteen bytes below its
    // own stack pointer. So each host page in the span is protected only if nothing that
    // survived this release still overlaps it.
    // In runs, not page by page. Each mprotect splits the kernel's map of this process,
    // and a 128MB heap released one 16KB page at a time is eight thousand of them; a few
    // of those and Darwin stops accepting mprotect at all, with EACCES, which surfaces
    // much later as a program that cannot be loaded. Consecutive pages that are all free
    // go in one call, which is almost always the whole span.
    uint64_t run_begin = 0;
    uint64_t run_end = 0;
    const auto flush = [&] {
        if (run_end <= run_begin) {
            return;
        }
        const uint64_t length = run_end - run_begin;
        // Mapped fresh rather than protected, which returns the range to exactly the state
        // the arena was reserved in. Protecting is not enough: a guest that mapped a file
        // here left a mapping whose *maximum* protection is the file's, and a read-only
        // file gives a range that can never be made writable again -- so the next program
        // loaded at that address fails to commit, with EACCES, a long way from the mmap
        // that caused it. This also drops the pages, which is what the madvise was for.
        if (!MapFreshAnonymous(run_begin, length)) {
            FATHOM_WARN("release at %#llx (%llu KB) failed: %s",
                        static_cast<unsigned long long>(run_begin),
                        static_cast<unsigned long long>(length / 1024), std::strerror(errno));
        }
        run_begin = run_end = 0;
    };
    for (uint64_t page = begin; page < end; page += page_size_) {
        bool occupied = false;
        for (const auto& range : committed_) {
            if (range.begin < page + page_size_ && range.end() > page) {
                occupied = true;
                break;
            }
        }
        if (occupied) {
            flush();
            continue;
        }
        if (run_end != page) {
            flush();
            run_begin = page;
        }
        run_end = page + page_size_;
    }
    flush();

    // And only the parts of it nothing else is still living in. A guest page is 4KB and a
    // host page 16KB, so the rounding above reaches up to three neighbouring guest pages
    // that are still in use; handing those back as free lets the arena allocate them to
    // somebody else while their owner is still running there.
    for (const auto& [free_begin, free_end] : UncommittedIn(begin, end)) {
        ReturnFreeExtent(free_begin, free_end - free_begin);
    }

    // Outside the lock: the observer goes into FEXCore, which asks this address space
    // about ranges while it invalidates, and would deadlock on the lock just released.
    lock.unlock();
    if (release_observer_ != nullptr) {
        release_observer_(begin, end);
    }
    return true;
}

bool GuestAddressSpace::Protect(uint64_t address, uint64_t size, int protection) {
    std::scoped_lock lock {mutex_};
    return ProtectLocked(address, size, protection);
}

// Callers already holding the lock use this directly. The list of committed ranges is
// rebuilt here, so a guest mprotect running while another thread commits or releases
// memory frees the vector's storage out from under whoever is walking it -- which shows
// up as a malloc abort a long way from the thread that caused it.
bool GuestAddressSpace::ProtectLocked(uint64_t address, uint64_t size, int protection) {
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
            updated.push_back(GuestRange {range.begin, begin - range.begin, range.protection, range.epoch});
        }
        const uint64_t overlap_begin = std::max(range.begin, begin);
        const uint64_t overlap_end = std::min(range.end(), end);
        updated.push_back(GuestRange {overlap_begin, overlap_end - overlap_begin,
                                      protection_for(overlap_begin, overlap_end, range.protection),
                                      range.epoch});
        if (range.end() > end) {
            updated.push_back(GuestRange {end, range.end() - end, range.protection, range.epoch});
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

std::vector<GuestRange> GuestAddressSpace::WritableRanges() const {
    std::scoped_lock lock {mutex_};
    std::vector<GuestRange> writable;
    writable.reserve(committed_.size());
    for (const auto& range : committed_) {
        if ((range.protection & kGuestProtWrite) != 0) {
            writable.push_back(range);
        }
    }
    return writable;
}

std::vector<GuestRange> GuestAddressSpace::WritableRangesIn(uint64_t begin, uint64_t end) const {
    std::scoped_lock lock {mutex_};
    std::vector<GuestRange> writable;
    for (const auto& range : committed_) {
        if (range.end() <= begin || range.begin >= end) {
            continue;
        }
        if ((range.protection & kGuestProtWrite) == 0) {
            continue;
        }
        const uint64_t low = std::max(range.begin, begin);
        const uint64_t high = std::min(range.end(), end);
        if (high > low) {
            writable.push_back(GuestRange {low, high - low, range.protection, range.epoch});
        }
    }
    return writable;
}

void GuestAddressSpace::FreeSpace(uint64_t* total, uint64_t* largest) const {
    std::scoped_lock lock {mutex_};
    uint64_t sum = 0;
    uint64_t biggest = 0;
    for (const auto& extent : free_) {
        sum += extent.size;
        biggest = std::max(biggest, extent.size);
    }
    if (total != nullptr) {
        *total = sum;
    }
    if (largest != nullptr) {
        *largest = biggest;
    }
}

bool GuestAddressSpace::RestoreIfUnchanged(uint64_t address, const void* bytes, uint64_t size,
                                           uint64_t epoch, const char** refusal) {
    static thread_local char why[192];
    const auto refuse = [&](const char* what, const GuestRange* range) {
        if (refusal != nullptr) {
            if (range != nullptr) {
                std::snprintf(why, sizeof(why), "%s (wanted epoch %llu, %#llx..%#llx is epoch %llu prot %d)",
                              what, static_cast<unsigned long long>(epoch),
                              static_cast<unsigned long long>(range->begin),
                              static_cast<unsigned long long>(range->end()),
                              static_cast<unsigned long long>(range->epoch), range->protection);
            } else {
                std::snprintf(why, sizeof(why), "%s", what);
            }
            *refusal = why;
        }
        return false;
    };
    std::scoped_lock lock {mutex_};
    uint64_t cursor = address;
    const uint64_t end = address + size;
    for (const auto& range : committed_) {
        if (range.end() <= cursor) {
            continue;
        }
        if (range.begin > cursor) {
            return refuse("nothing is mapped there any more", &range);
        }
        if (range.epoch != epoch) {
            return refuse("a different mapping is there now", &range);
        }
        if ((range.protection & kGuestProtWrite) == 0) {
            return refuse("it is no longer writable", &range);
        }
        cursor = range.end();
        if (cursor >= end) {
            // The arena saying a range is writable is not the host saying so. A guest that
            // mapped a file here left a mapping whose maximum protection the file decided,
            // and a guest mprotect that widened it afterwards failed quietly. Writing
            // anyway is a protection fault inside this memcpy, which kills the session --
            // so the host is asked first, and told no is a reason to leave the copy alone.
            const uint64_t page_begin = AlignDown(address);
            const uint64_t page_end = AlignUp(end);
            if (mprotect(reinterpret_cast<void*>(page_begin), page_end - page_begin,
                         PROT_READ | PROT_WRITE) != 0) {
                return refuse("the host will not allow writing there", nullptr);
            }
            std::memcpy(reinterpret_cast<void*>(address), bytes, size);
            return true;
        }
    }
    return refuse("the mapping ends short of the copy", nullptr);
}

uint64_t GuestAddressSpace::EpochAt(uint64_t address) const {
    std::scoped_lock lock {mutex_};
    for (const auto& range : committed_) {
        if (range.begin <= address && address < range.end()) {
            return range.epoch;
        }
    }
    return 0;
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
