# Faultline

An anticheat proof of concept that detects execution from manually mapped memory by monitoring working set page faults and walking the call stack of suspicious threads.

## How it works

Windows tracks page faults per process through the working set watch API (`InitializeProcessForWsWatch` / `GetWsChangesEx`). Every time a page is brought into the working set, the OS records the instruction pointer (`FaultingPc`) that triggered the fault.

Faultline polls these events, checks whether each `FaultingPc` falls within a known loaded module, and flags execution from memory regions that are executable but not backed by any module in the PEB. When a suspicious fault is detected, the faulting thread is suspended and its stack is walked to capture the full call chain.

This catches code that was injected via manual mapping, `VirtualAllocEx` + `WriteProcessMemory`, or similar techniques where the executable memory is never registered with the Windows loader.

## Components

| Directory  | Description |
|------------|-------------|
| `anticheat/`  | Core detection DLL. Monitors working set faults, classifies memory regions, walks stacks |
| `host/`    | Minimal target process that loads the detection DLL |
| `injector/`| Manual mapper that injects the test payload into the host process |
| `payload/` | Test DLL that executes from manually mapped memory to trigger detection |
| `shared/`   | Common headers (logger, RAII handles, utilities)

## Usage

1. Start `host.exe`
2. Run `injector.exe` in a separate terminal
3. The host console will log any detected suspicious execution along with stack traces

## Demo

<img width="2408" height="868" alt="image" src="https://github.com/user-attachments/assets/dfcbaa5e-5e84-4a82-9df3-ad8bfe965e56" />

## Limitations

- The working set watch API only fires on the first access to a page. Once a page is resident in the working set, further execution from it is invisible.
- Detection is reactive. By the time the fault is observed, the injected code has already run.
- Code caves or patches within legitimate modules will not be caught since the `FaultingPc` resolves to a known module range.
- The poll-based design means short lived threads may exit before a stack walk can be performed.
