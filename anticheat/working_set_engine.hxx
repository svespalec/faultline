#pragma once

#include "engine.hxx"
#include "module_checker.hxx"
#include "stack_walk.hxx"

#include <unordered_set>

class WorkingSetEngine : public IEngine {
public:
  explicit WorkingSetEngine( ModuleChecker& Checker );

  void Start() override;
  void Stop() override;

private:
  static DWORD WINAPI ThreadProc( LPVOID Param );

  void Poll();
  void ProcessEntries( std::size_t Count );
  void OnSuspiciousPc( const PcInfo& Info, std::uintptr_t Tid );
  void ScanWorkingSet();
  void OnSuspiciousRegion( std::uintptr_t Page );

  ModuleChecker& Checker;
  SafeHandle Thread;
  std::atomic<bool> Running = false;

  //
  // Allocation bases already reported, used to dedupe across both the
  // Pc-based event path and the full-WS snapshot path.
  //
  std::unordered_set<std::uintptr_t> FlaggedAllocBases;
};
