#pragma once

class IEngine {
public:
  virtual ~IEngine() = default;
  virtual void Start() = 0;
  virtual void Stop() = 0;
};
