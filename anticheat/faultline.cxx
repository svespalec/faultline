#include <shared/stdafx.hxx>
#include "faultline.hxx"
#include "working_set_engine.hxx"

void Faultline::Start() {
  //
  // Set up the symbol engine for stack resolution
  //
  SymSetOptions( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );
  SymInitialize( GetCurrentProcess(), nullptr, TRUE );

  //
  // Register and start all engines
  //
  Engines.push_back( std::make_unique<WorkingSetEngine>( Checker ) );

  for ( auto& Engine : Engines ) {
    Engine->Start();
  }

  LOG_OK( "Faultline started" );
}

void Faultline::Stop() {
  //
  // Stop engines in reverse order
  //
  for ( auto It = Engines.rbegin(); It != Engines.rend(); ++It ) {
    ( *It )->Stop();
  }

  Engines.clear();

  SymCleanup( GetCurrentProcess() );

  LOG_INFO( "Faultline stopped" );
}
