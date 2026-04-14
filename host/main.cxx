#include <shared/stdafx.hxx>

using FaultlineFn = void( * )();

//
// Fake game loop that runs on its own thread.
// Gives the injector a stable, long-lived thread to hijack.
//
static DWORD WINAPI GameThread( LPVOID ) {
  LOG_STEP( "Game thread started (TID {})", GetCurrentThreadId() );

  while ( true ) {
    Sleep( 16 ); // ~60 fps tick
  }

  return 0;
}

int main() {
  auto Dll = LoadLibraryA( "anticheat.dll" );

  if ( !Dll ) {
    std::printf( "Failed to load anticheat.dll: %lu\n", GetLastError() );
    return 1;
  }

  auto Start = reinterpret_cast<FaultlineFn>( GetProcAddress( Dll, "StartFaultline" ) );
  auto Stop = reinterpret_cast<FaultlineFn>( GetProcAddress( Dll, "StopFaultline" ) );

  if ( !Start || !Stop ) {
    std::printf( "Failed to resolve exports: %lu\n", GetLastError() );
    return 1;
  }

  Start();

  //
  // Spin up a game thread for the injector to hijack
  //
  SafeHandle Game( CreateThread( nullptr, 0, GameThread, nullptr, 0, nullptr ) );

  //
  // Keep the host alive while faultline runs.
  //
  std::getchar();

  Stop();

  return 0;
}
