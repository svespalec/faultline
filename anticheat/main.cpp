#include <shared/stdafx.hpp>

#include <dbghelp.h>

#pragma comment( lib, "dbghelp.lib" )
#pragma comment( lib, "psapi.lib" )

#define DLL_EXPORT extern "C" __declspec(dllexport)

HANDLE MonitorThread = nullptr;

static DWORD WINAPI MonitorThreadProc( LPVOID ) {
  std::printf( "Running Monitor Thread" );

  return 0;
}

DLL_EXPORT void StartFaultLine() {
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

  MonitorThread = CreateThread( nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr );

  if ( !MonitorThread ) {
    std::printf( "Failed to create monitor thread: %lu", GetLastError() );
  }
}

DLL_EXPORT void StopFaultLine() {
  if ( MonitorThread ) {
    WaitForSingleObject( MonitorThread, 2000 );
    CloseHandle( MonitorThread );
    MonitorThread = nullptr;
  }

  SymCleanup( GetCurrentProcess() );
}