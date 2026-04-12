#include <shared/stdafx.hpp>

using FaultLineFn = void( * )();

int main() {
  auto Dll = LoadLibraryA( "anticheat.dll" );

  if ( !Dll ) {
    std::printf( "Failed to load anticheat.dll: %lu\n", GetLastError() );
    return 1;
  }

  auto Start = reinterpret_cast<FaultLineFn>( GetProcAddress( Dll, "StartFaultLine" ) );
  auto Stop = reinterpret_cast<FaultLineFn>( GetProcAddress( Dll, "StopFaultLine" ) );

  if ( !Start || !Stop ) {
    std::printf( "Failed to resolve exports: %lu\n", GetLastError() );
    return 1;
  }

  Start();

  //
  // Keep the host alive while faultline runs.
  //
  std::getchar();

  Stop();

  return 0;
}
