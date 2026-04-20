#include <shared/stdafx.hxx>
#include <shared/utils.hxx>
#include "working_set_engine.hxx"

#include <tlhelp32.h>

constexpr std::size_t BufferEntries = 4096;
constexpr int RefreshEvery = 50; // Re-enumerate modules every N polls
constexpr DWORD PollIntervalMs = 100;

//
// Static buffer to avoid large per-call stack allocations
//
static PSAPI_WS_WATCH_INFORMATION_EX WatchBuffer[ BufferEntries ]{};

[[nodiscard]] static std::string_view ProtectionName( unsigned long Protection ) noexcept {
  switch ( Protection & 0xFFu ) {
    case PAGE_EXECUTE:
      return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:
      return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE:
      return "PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY:
      return "PAGE_EXECUTE_WRITECOPY";
    case PAGE_READONLY:
      return "PAGE_READONLY";
    case PAGE_READWRITE:
      return "PAGE_READWRITE";
    default:
      return "PAGE_UNKNOWN";
  }
}

WorkingSetEngine::WorkingSetEngine( ModuleChecker& Checker )
  : Checker( Checker )
{
  //
  // Required once per process before GetWsChangesEx reports entries
  //
  if ( !InitializeProcessForWsWatch( GetCurrentProcess() ) ) {
    LOG_ERROR( "InitializeProcessForWsWatch failed: {}", GetLastError() );
  }
}

void WorkingSetEngine::Start() {
  if ( Thread ) {
    return;
  }

  Running = true;

  Thread.Handle = CreateThread( nullptr, 0, ThreadProc, this, 0, nullptr );

  if ( !Thread ) {
    LOG_ERROR( "WorkingSetEngine: failed to create thread: {}", GetLastError() );
    Running = false;
    return;
  }

  LOG_OK( "WorkingSetEngine started" );
}

void WorkingSetEngine::Stop() {
  Running = false;

  if ( Thread ) {
    WaitForSingleObject( Thread, 2000 );
  }

  LOG_INFO( "WorkingSetEngine stopped" );
}

DWORD WINAPI WorkingSetEngine::ThreadProc( LPVOID Param ) {
  auto* Self = static_cast<WorkingSetEngine*>( Param );

  Self->Poll();

  return 0;
}

void WorkingSetEngine::Poll() {
  int Iteration = 0;

  while ( Running ) {
    if ( Iteration % RefreshEvery == 0 ) {
      Checker.Refresh();
    }

    ++Iteration;

    auto BufBytes = static_cast<DWORD>( BufferEntries * sizeof( PSAPI_WS_WATCH_INFORMATION_EX ) );

    if ( GetWsChangesEx( GetCurrentProcess(), WatchBuffer, &BufBytes ) ) {
      auto Count = static_cast<std::size_t>( BufBytes ) / sizeof( PSAPI_WS_WATCH_INFORMATION_EX );
      ProcessEntries( Count );
    } else if ( GetLastError() == ERROR_MORE_DATA ) {
      //
      // Buffer overflowed, some faults were lost. Process what we got
      //
      LOG_WARN( "Working set watch buffer overflow, some faults were lost" );

      auto Count = static_cast<std::size_t>( BufBytes ) / sizeof( PSAPI_WS_WATCH_INFORMATION_EX );
      ProcessEntries( Count );
    }

    Sleep( PollIntervalMs );
  }
}

void WorkingSetEngine::ProcessEntries( std::size_t Count ) {
  for ( std::size_t I = 0; I < Count; ++I ) {
    const auto& Entry = WatchBuffer[ I ];
    auto Pc = reinterpret_cast<std::uintptr_t>( Entry.BasicInfo.FaultingPc );
    auto Va = reinterpret_cast<std::uintptr_t>( Entry.BasicInfo.FaultingVa );

    if ( Pc == 0 && Va == 0 ) {
      break;
    }

    if ( Pc == 0 ) {
      continue; // no user-mode PC to classify
    }

    auto Info = Checker.Classify( Pc );

    if ( Info.Suspicious() ) {
      OnSuspiciousPc( Info, static_cast<std::uintptr_t>( Entry.FaultingThreadId ) );
    }
  }

  ScanWorkingSet();
}

void WorkingSetEngine::OnSuspiciousPc(
  const PcInfo& Info,
  std::uintptr_t Tid
) {
  if ( FlaggedAllocBases.contains( Info.AllocationBase ) ) {
    return;
  }
  FlaggedAllocBases.insert( Info.AllocationBase );

  LOG_INFO( "---------------------- Detection ----------------------" );
  LOG_ERROR( "Suspicious execution @ PC {:#018x}", Info.Pc );
  LOG_INFO( "TID: {}", Tid );
  LOG_INFO( "Region: [{:#018x} - {:#018x}]", Info.RegionBase, Info.RegionEnd );
  LOG_INFO( "Alloc base: {:#018x}", Info.AllocationBase );
  LOG_INFO( "Type: {}", Info.AllocationTypeName() );
  LOG_INFO( "Protection: {} ({:#010x})", ProtectionName( Info.Protection ), Info.Protection );

  auto Frames = CaptureStack( Tid, Checker );

  if ( Frames.empty() ) {
    LOG_INFO( "Stack: failed or thread already exited" );
    LOG_INFO( "------------------------------------------------------" );
    return;
  }

  LOG_INFO( "Stack ({} frames):", Frames.size() );

  for ( std::size_t I = 0; I < Frames.size(); ++I ) {
    const auto& F = Frames[ I ];
    auto Label = F.ModuleName.empty() ? "???" : F.ModuleName;

    LOG_INFO( " [{}] {:#018x} [{}]{}",
      I, F.Pc, Label,
      F.WithinKnownModule ? "" : " <-- OUTSIDE KNOWN MODULE"
    );
  }

  LOG_INFO( "------------------------------------------------------" );
}

//
// Find a thread with any stack frame inside the region. RIP alone misses
// payloads blocked in Sleep / WaitForSingle / etc.
//
static DWORD FindThreadInRegion(
  std::uintptr_t Begin,
  std::uintptr_t End,
  const ModuleChecker& Checker,
  std::vector<StackFrame>& OutFrames
) {
  SafeHandle Snap( CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) );

  if ( !Snap ) {
    return 0;
  }

  DWORD MyPid = GetCurrentProcessId();
  DWORD MyTid = GetCurrentThreadId();

  THREADENTRY32 Entry{};
  Entry.dwSize = sizeof( Entry );

  if ( !Thread32First( Snap, &Entry ) ) {
    return 0;
  }

  do {
    if ( Entry.th32OwnerProcessID != MyPid ) {
      continue;
    }

    if ( Entry.th32ThreadID == MyTid ) {
      continue;
    }

    auto Frames = CaptureStack(
      static_cast<std::uintptr_t>( Entry.th32ThreadID ),
      Checker
    );

    for ( const auto& F : Frames ) {
      if ( F.Pc >= Begin && F.Pc < End ) {
        OutFrames = std::move( Frames );
        return Entry.th32ThreadID;
      }
    }
  } while ( Thread32Next( Snap, &Entry ) );

  return 0;
}

void WorkingSetEngine::ScanWorkingSet() {
  //
  // QueryWorkingSet covers pages the event stream doesn't report -- most
  // notably cross-process writes for the RW -> RX manual-map flow. Buffer
  // grows on ERROR_BAD_LENGTH, NumberOfEntries is the required count.
  //
  static std::vector<std::uint8_t> Buffer(
    sizeof( ULONG_PTR ) + 16384 * sizeof( PSAPI_WORKING_SET_BLOCK )
  );

  auto Info = reinterpret_cast<PSAPI_WORKING_SET_INFORMATION*>( Buffer.data() );

  while ( !QueryWorkingSet( GetCurrentProcess(), Info, static_cast<DWORD>( Buffer.size() ) ) ) {
    if ( GetLastError() != ERROR_BAD_LENGTH ) {
      LOG_ERROR( "QueryWorkingSet failed: {}", GetLastError() );
      return;
    }

    auto Needed = sizeof( ULONG_PTR )
                + ( Info->NumberOfEntries + 1024 ) * sizeof( PSAPI_WORKING_SET_BLOCK );
    Buffer.resize( Needed );
    Info = reinterpret_cast<PSAPI_WORKING_SET_INFORMATION*>( Buffer.data() );
  }

  for ( ULONG_PTR I = 0; I < Info->NumberOfEntries; ++I ) {
    const auto& Block = Info->WorkingSetInfo[ I ];

    //
    // Bit 1 is the execute bit across every variant of the 5-bit PTE
    // encoding (plain, guard, non-cacheable, and combinations).
    //
    if ( ( Block.Protection & 0x2u ) == 0 ) {
      continue;
    }

    std::uintptr_t Page = static_cast<std::uintptr_t>( Block.VirtualPage ) << 12;

    if ( Checker.IsKnownPc( Page ) ) {
      continue;
    }

    //
    // Cache miss may just mean a DLL mapped RX but not yet linked into
    // PEB.Ldr -- GetModuleHandleEx can't see those either. Allocation
    // type is stable across that window: legit modules are MEM_IMAGE,
    // our VirtualAlloc'd target is MEM_PRIVATE.
    //
    MEMORY_BASIC_INFORMATION Mbi{};

    if ( VirtualQuery( reinterpret_cast<void*>( Page ), &Mbi, sizeof( Mbi ) ) != sizeof( Mbi ) ) {
      continue;
    }

    if ( Mbi.Type == MEM_IMAGE ) {
      continue;
    }

    OnSuspiciousRegion( Page );
  }
}

void WorkingSetEngine::OnSuspiciousRegion( std::uintptr_t Page ) {
  auto Info = Checker.Classify( Page );

  if ( FlaggedAllocBases.contains( Info.AllocationBase ) ) {
    return;
  }
  FlaggedAllocBases.insert( Info.AllocationBase );

  LOG_INFO( "---------------------- Detection ----------------------" );
  LOG_ERROR( "Suspicious executable region @ {:#018x}", Page );
  LOG_INFO( "Region: [{:#018x} - {:#018x}]", Info.RegionBase, Info.RegionEnd );
  LOG_INFO( "Alloc base: {:#018x}", Info.AllocationBase );
  LOG_INFO( "Type: {}", Info.AllocationTypeName() );
  LOG_INFO( "Protection: {} ({:#010x})", ProtectionName( Info.Protection ), Info.Protection );
  LOG_INFO( "Source: WS snapshot" );

  std::vector<StackFrame> Frames;
  auto Tid = FindThreadInRegion( Info.RegionBase, Info.RegionEnd, Checker, Frames );

  if ( Tid == 0 ) {
    LOG_INFO( "No thread currently in region (finished or not yet started)" );
    LOG_INFO( "------------------------------------------------------" );
    return;
  }

  LOG_INFO( "Executing thread: {}", Tid );

  LOG_INFO( "Stack ({} frames):", Frames.size() );

  for ( std::size_t I = 0; I < Frames.size(); ++I ) {
    const auto& F = Frames[ I ];
    auto Label = F.ModuleName.empty() ? "???" : F.ModuleName;

    LOG_INFO( " [{}] {:#018x} [{}]{}",
      I, F.Pc, Label,
      F.WithinKnownModule ? "" : " <-- OUTSIDE KNOWN MODULE"
    );
  }

  LOG_INFO( "------------------------------------------------------" );
}
