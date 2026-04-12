#pragma once

#include "module_checker.hxx"

#include <dbghelp.h>

#pragma comment( lib, "dbghelp.lib" )

struct StackFrame {
  std::uintptr_t Pc{};
  bool WithinKnownModule{};
  std::string ModuleName{};
};

[[nodiscard]] std::vector<StackFrame> CaptureStack( std::uintptr_t ThreadId, const ModuleChecker& Checker );
