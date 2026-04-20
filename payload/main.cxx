#include <shared/stdafx.hxx>

//
// Payload entrypoint called by the injector via CreateRemoteThread or thread hijack.
// The image is manually mapped so it won't appear in PEB module lists.
//
extern "C" __declspec( dllexport ) DWORD WINAPI PayloadRun( LPVOID ) {
  LOG_WARN( "Payload executing from manually-mapped memory" );

  //
  // Stay alive long enough for the WS monitor to poll and stackwalk this thread
  //
  Sleep( 2000 );

  return 0;
}

BOOL WINAPI DllMain( HINSTANCE, DWORD, LPVOID ) {
  return TRUE;
}
