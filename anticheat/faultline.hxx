#pragma once

#include "engine.hxx"
#include "module_checker.hxx"

class Faultline {
public:
  void Start();
  void Stop();

private:
  ModuleChecker Checker;
  std::vector<std::unique_ptr<IEngine>> Engines;
};
