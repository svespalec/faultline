#include <shared/stdafx.hxx>
#include "module_checker.hxx"

std::string_view PcInfo::AllocationTypeName() const noexcept {
  switch ( AllocationType ) {
    case MEM_IMAGE:
      return "MEM_IMAGE";
    case MEM_MAPPED:
      return "MEM_MAPPED";
    case MEM_PRIVATE:
      return "MEM_PRIVATE";
    default:
      return "MEM_UNKNOWN";
  }
}

void ModuleChecker::Refresh() {
  // TODO: EnumProcessModules -> build sorted range table
}

PcInfo ModuleChecker::Classify( std::uintptr_t Pc ) const {
  // TODO: VirtualQuery + IsKnownPc -> full classification
  return PcInfo{ .Pc = Pc };
}

bool ModuleChecker::IsKnownPc( std::uintptr_t Pc ) const {
  // TODO: binary search over Ranges
  static_cast<void>( Pc );
  return true;
}
