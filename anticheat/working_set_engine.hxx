#pragma once

#include "engine.hxx"
#include "module_checker.hxx"
#include "stack_walk.hxx"

class WorkingSetEngine : public IEngine {
public:
  explicit WorkingSetEngine( ModuleChecker& Checker );

  void Start() override;
  void Stop() override;

private:
  static DWORD WINAPI ThreadProc( LPVOID Param );

  void Poll();
  void ProcessEntries();
  void OnSuspiciousPc( const PcInfo& Info, std::uintptr_t Va, std::uintptr_t Tid );

  ModuleChecker& Checker;
  SafeHandle Thread;
  bool Running = false;
};
