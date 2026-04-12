#pragma once

// DLL projects set FAULTLINE_EXPORT in their CMakeLists.txt
#ifdef FAULTLINE_EXPORT
  #define ANTICHEAT_API extern "C" __declspec(dllexport)
#else
  #define ANTICHEAT_API extern "C" __declspec(dllimport)
#endif
