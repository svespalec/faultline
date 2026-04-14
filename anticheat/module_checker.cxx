#include <shared/stdafx.hxx>
#include <shared/utils.hxx>
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
  auto Process = GetCurrentProcess();
  DWORD BytesNeeded = 0;

  if ( !EnumProcessModules( Process, nullptr, 0, &BytesNeeded ) || BytesNeeded == 0 ) {
    Ranges.clear();
    return;
  }

  std::vector<HMODULE> Modules( BytesNeeded / sizeof( HMODULE ) );

  if ( !EnumProcessModules( Process, Modules.data(),
    static_cast<DWORD>( Modules.size() * sizeof( HMODULE ) ),
    &BytesNeeded ) ) {
    Ranges.clear();
    return;
  }

  Modules.resize( BytesNeeded / sizeof( HMODULE ) );

  std::vector<ModuleRange> Next;
  Next.reserve( Modules.size() );

  for ( auto Mod : Modules ) {
    MODULEINFO Info{};

    if ( !GetModuleInformation( Process, Mod, &Info, sizeof( Info ) ) ) {
      continue;
    }

    auto Base = reinterpret_cast<std::uintptr_t>( Info.lpBaseOfDll );

    Next.push_back( { Base, Base + Info.SizeOfImage } );
  }

  std::ranges::sort( Next, {}, &ModuleRange::Base );

  Ranges = std::move( Next );
}

bool ModuleChecker::IsKnownPc( std::uintptr_t Pc ) const {
  //
  // If we have no modules, don't silently trust everything
  //
  if ( Ranges.empty() ) {
    return false;
  }

  //
  // Ranges are sorted by Base. upper_bound finds the first module that
  // starts *after* Pc, then we step back one, if Pc is inside any
  // module, it has to be that one. Then check Pc < End to confirm
  //
  auto It = std::ranges::upper_bound( Ranges, Pc, {}, &ModuleRange::Base );

  if ( It == Ranges.begin() ) {
    return false;
  }

  --It;

  return Pc < It->End;
}

PcInfo ModuleChecker::Classify( std::uintptr_t Pc ) const {
  PcInfo Result{
    .Pc = Pc,
    .WithinKnownModule = IsKnownPc( Pc ),
  };

  MEMORY_BASIC_INFORMATION PageInfo{};

  if ( VirtualQuery( reinterpret_cast<void*>( Pc ), &PageInfo, sizeof( PageInfo ) ) == 0 ) {
    return Result;
  }

  Result.RegionBase     = reinterpret_cast<std::uintptr_t>( PageInfo.BaseAddress );
  Result.RegionEnd      = Result.RegionBase + PageInfo.RegionSize;
  Result.AllocationBase = reinterpret_cast<std::uintptr_t>( PageInfo.AllocationBase );
  Result.Protection     = PageInfo.Protect;
  Result.AllocationType = PageInfo.Type;
  Result.Executable     = PageInfo.State == MEM_COMMIT && IsExecutablePage( PageInfo.Protect );

  return Result;
}
