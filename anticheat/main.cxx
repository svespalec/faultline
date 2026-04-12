#include <shared/stdafx.hxx>
#include <shared/safe_handle.hxx>
#include "stack_walk.hxx"

SafeHandle MonitorThread;

static DWORD WINAPI MonitorThreadProc( LPVOID ) {
  std::printf( "Running Monitor Thread" );

  return 0;
}

DLL_EXPORT void StartFaultline() {
  //
  // Check if we're already running.
  //
  if ( MonitorThread ) {
    return;
  }

  //
  // Set up symbolic context engine
  //
  SymSetOptions( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );
  SymInitialize( GetCurrentProcess(), nullptr, TRUE );

  MonitorThread.Handle = CreateThread( nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr );

  if ( !MonitorThread ) {
    std::printf( "Failed to create monitor thread: %lu", GetLastError() );
  }
}

DLL_EXPORT void StopFaultline() {
  if ( MonitorThread ) {
    WaitForSingleObject( MonitorThread, 2000 );
  }

  SymCleanup( GetCurrentProcess() );
}