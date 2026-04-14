#include <shared/stdafx.hxx>
#include "working_set_engine.hxx"

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
      continue; // Kernel-origin fault, no user-mode PC
    }

    auto Info = Checker.Classify( Pc );

    if ( Info.Suspicious() ) {
      OnSuspiciousPc( Info, Va, static_cast<std::uintptr_t>( Entry.FaultingThreadId ) );
    }
  }
}

void WorkingSetEngine::OnSuspiciousPc(
  const PcInfo& Info,
  std::uintptr_t Va,
  std::uintptr_t Tid
) {
  LOG_ERROR( "Suspicious execution @ pc {:#018x}", Info.Pc );
  LOG_INFO( "  Va: {:#018x}", Va );
  LOG_INFO( "  TID: {}", Tid );
  LOG_INFO( "  Region: [{:#018x} - {:#018x}]", Info.RegionBase, Info.RegionEnd );
  LOG_INFO( "  Alloc base: {:#018x}", Info.AllocationBase );
  LOG_INFO( "  Type: {}", Info.AllocationTypeName() );
  LOG_INFO( "  Protection: {} ({:#010x})", ProtectionName( Info.Protection ), Info.Protection );
  LOG_INFO( "  Known module: {}", Info.WithinKnownModule ? "Yes" : "No" );

  auto Frames = CaptureStack( Tid, Checker );

  if ( Frames.empty() ) {
    LOG_INFO( "  Stack walk: failed or thread already exited" );
    return;
  }

  LOG_INFO( "  Stack trace ({} frames):", Frames.size() );

  for ( std::size_t I = 0; I < Frames.size(); ++I ) {
    const auto& F = Frames[ I ];
    auto Label = F.ModuleName.empty() ? "???" : F.ModuleName;

    LOG_INFO( "    [{}] {:#018x} [{}]{}",
      I, F.Pc, Label,
      F.WithinKnownModule ? "" : " <-- OUTSIDE KNOWN MODULE"
    );
  }
}
