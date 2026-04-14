#include <shared/stdafx.hxx>

//
// Payload entrypoint called by the injector via CreateRemoteThread or thread hijack.
// The image is manually mapped so it won't appear in PEB module lists.
//
extern "C" __declspec( dllexport ) DWORD WINAPI PayloadRun( LPVOID ) {
  constexpr std::size_t PageSize = 4096;

  //
  // Commit a fresh private page and write to it.
  // The soft fault gives GetWsChangesEx a FaultingPc inside this mapped region (hooray!)
  //
  auto* Page = reinterpret_cast<BYTE*>( VirtualAlloc(
    nullptr,
    PageSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  ) );

  if ( Page ) {
    Page[ 0 ] = 0x41;
    VirtualFree( Page, 0, MEM_RELEASE );
  }

  LOG_STEP( "Payload executing from manually-mapped memory" );

  //
  // Stay alive long enough for the WS monitor to poll and stackwalk this thread
  //
  Sleep( 2000 );

  return 0;
}

BOOL WINAPI DllMain( HINSTANCE, DWORD, LPVOID ) {
  return TRUE;
}
