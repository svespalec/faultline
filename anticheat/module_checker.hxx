#pragma once

#include <psapi.h>

#pragma comment( lib, "psapi.lib" )

struct ModuleRange {
  std::uintptr_t Base{};
  std::uintptr_t End{}; // Base + SizeOfImage
};

struct PcInfo {
  std::uintptr_t Pc{};

  std::uintptr_t RegionBase{};
  std::uintptr_t RegionEnd{};
  std::uintptr_t AllocationBase{};

  unsigned long Protection{};
  unsigned long AllocationType{};

  bool WithinKnownModule{};
  bool Executable{};

  [[nodiscard]] bool Suspicious() const noexcept {
    return Executable && !WithinKnownModule;
  }

  [[nodiscard]] std::string_view AllocationTypeName() const noexcept;
};

class ModuleChecker {
public:
  // Rebuild the sorted range table from the current module list.
  void Refresh();

  // Classify the memory backing a PC against the current module snapshot.
  [[nodiscard]] PcInfo Classify( std::uintptr_t Pc ) const;

  // Check whether a PC falls within a known module range.
  [[nodiscard]] bool IsKnownPc( std::uintptr_t Pc ) const;

private:
  std::vector<ModuleRange> Ranges; // sorted by Base
};
