#pragma once

struct SafeHandle {
  HANDLE Handle = nullptr;

  SafeHandle() = default;
  SafeHandle( HANDLE Handle ) : Handle( Handle ) {}

  ~SafeHandle() {
    if ( Handle ) {
      CloseHandle( Handle );
    }
  }

  SafeHandle( const SafeHandle& ) = delete;
  SafeHandle& operator=( const SafeHandle& ) = delete;

  operator HANDLE() const {
    return Handle;
  }

  explicit operator bool() const {
    return Handle != nullptr;
  }
};
