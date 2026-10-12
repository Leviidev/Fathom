// SPDX-License-Identifier: MIT
#pragma once

#include "Interface/IR/IR.h"
#include <cstdint>

namespace FEXCore::IR {
class IREmitter;

struct AddressMode {
  Ref Segment {nullptr};
  Ref Base {nullptr};
  Ref Index {nullptr};
  int64_t Offset = 0;

  MemOffsetType IndexType = MemOffsetType::SXTX;
  uint8_t IndexScale = 1;

  // Size in bytes for the address calculation. 8 for an arm64 hardware mode.
  IR::OpSize AddrSize;
  bool NonTSO;
  // Base already holds a host address -- it came out of MakeSegmentAddress, which relocates
  // -- so the guest memory base must not be added a second time. A 32-bit guest got away
  // without this: its addresses are cut to 32 bits before the base goes on, which strips a
  // base added twice. A 64-bit guest's are not.
  bool Host = false;
};

Ref LoadEffectiveAddress(IREmitter* IREmit, const AddressMode& A, IR::OpSize GPRSize, bool AddSegmentBase, bool AllowUpperGarbage = false);
AddressMode SelectAddressMode(IREmitter* IREmit, const AddressMode& A, IR::OpSize GPRSize, bool HostSupportsTSOImm9, bool AtomicTSO,
                              bool Vector, IR::OpSize AccessSize);

} // namespace FEXCore::IR