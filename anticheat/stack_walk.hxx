#pragma once

#include <dbghelp.h>

#pragma comment( lib, "dbghelp.lib" )
#pragma comment( lib, "psapi.lib" )

struct StackFrame {
  //
  // Program Counter (instruction pointer)
  //
  std::uintptr_t Pc{};

  //
  // If the frame's pc is within a valid module
  //
  bool InValidModule{};

  //
  // E.g "ntdll.dll", empty if unknown
  //
  std::string ModuleName{};
};

[[nodiscard]] std::vector<StackFrame> CaptureStack( std::uintptr_t ThreadId );