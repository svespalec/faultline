#include <shared/stdafx.hxx>
#include <shared/utils.hxx>
#include "stack_walk.hxx"

constexpr std::size_t MaxFrames = 64;

std::vector<StackFrame> CaptureStack( std::uintptr_t ThreadId, const ModuleChecker& Checker ) {
  std::vector<StackFrame> Frames{};

  //
  // Open the target thread for stack inspection.
  //
  constexpr auto Access = THREAD_SUSPEND_RESUME
                        | THREAD_GET_CONTEXT
                        | THREAD_QUERY_INFORMATION;

  SafeHandle Target( OpenThread( Access, FALSE, static_cast<DWORD>( ThreadId ) ) );

  if ( !Target ) {
    LOG_ERROR( "Failed to open thread {}", ThreadId );
    return Frames;
  }

  //
  // Freeze the thread so we can safely read its context.
  //
  if ( SuspendThread( Target ) == static_cast<DWORD>( -1 ) ) {
    LOG_ERROR( "Failed to suspend thread {}", ThreadId );
    return Frames;
  }

  CONTEXT Ctx{};
  Ctx.ContextFlags = CONTEXT_FULL;

  if ( !GetThreadContext( Target, &Ctx ) ) {
    LOG_ERROR( "Failed to get context for thread {}", ThreadId );
    ResumeThread( Target );
    return Frames;
  }

  //
  // Set up the initial stack frame from the thread's registers.
  //
  STACKFRAME64 Sf{};

  Sf.AddrPC.Offset    = Ctx.Rip;
  Sf.AddrPC.Mode      = AddrModeFlat;
  Sf.AddrFrame.Offset = Ctx.Rbp;
  Sf.AddrFrame.Mode   = AddrModeFlat;
  Sf.AddrStack.Offset = Ctx.Rsp;
  Sf.AddrStack.Mode   = AddrModeFlat;

  auto Process = GetCurrentProcess();

  Frames.reserve( MaxFrames );

  //
  // Walk the call stack frame by frame.
  //
  for ( std::size_t I = 0; I < MaxFrames; ++I ) {
    if ( !StackWalk64(
      IMAGE_FILE_MACHINE_AMD64,
      Process,
      Target,
      &Sf, &Ctx, nullptr,
      SymFunctionTableAccess64,
      SymGetModuleBase64,
      nullptr ) ) {
      break;
    }

    if ( Sf.AddrPC.Offset == 0 ) {
      break;
    }

    auto Pc = static_cast<std::uintptr_t>( Sf.AddrPC.Offset );

    //
    // Stop at obviously bogus frames from corrupted stacks (e.g. after thread hijack).
    // Below 64K is never valid usermode code, above 0x7FFF'FFFFFFFF is kernel space,
    // and 0xCCCCCCCC is just MSVC uninitialized stack fill.
    //
    if ( Pc < 0x10000 || Pc > 0x7FFF'FFFFFFFF || ( Pc & 0xFFFFFFFF ) == 0xCCCCCCCC ) {
      break;
    }

    Frames.push_back( {
      .Pc                = Pc,
      .WithinKnownModule = Checker.IsKnownPc( Pc ),
      .ModuleName        = ModuleNameFromAddress( Pc ),
    } );
  }

  ResumeThread( Target );

  return Frames;
}
