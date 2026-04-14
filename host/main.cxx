#include <shared/stdafx.hxx>

using FaultlineFn = void( * )();

//
// Fake game loop that runs on its own thread.
// Gives the injector a stable, long-lived thread to hijack.
//
static DWORD GameTid = 0;

static DWORD WINAPI GameThread( LPVOID ) {
  GameTid = GetCurrentThreadId();

  LOG_STEP( "Game thread started (TID {})", GameTid );

  while ( true ) {
    Sleep( 16 ); // ~60 fps tick
  }

  return 0;
}

//
// Publish the game thread TID via named shared memory so the injector can find the right thread to hijack
//
static SafeHandle SharedMapping;

static void PublishGameTid() {
  SharedMapping.Handle = CreateFileMappingA(
    INVALID_HANDLE_VALUE,
    nullptr,
    PAGE_READWRITE,
    0,
    sizeof( DWORD ),
    "FaultlineGameTid"
  );

  if ( !SharedMapping ) {
    return;
  }

  auto* Ptr = static_cast<DWORD*>(
    MapViewOfFile( SharedMapping, FILE_MAP_WRITE, 0, 0, sizeof( DWORD ) )
  );

  if ( Ptr ) {
    *Ptr = GameTid;
    UnmapViewOfFile( Ptr );

    LOG_OK( "Published game thread TID {} via shared memory", GameTid );
  }
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
  // Give the game thread time to start, then publish its TID
  //
  Sleep( 100 );

  PublishGameTid();

  //
  // Keep the host alive while faultline runs
  //
  std::getchar();

  Stop();

  return 0;
}
