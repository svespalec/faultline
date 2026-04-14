# Faultline

An anticheat proof of concept that detects execution from manually mapped memory by monitoring working set page faults and walking the call stack of suspicious threads.

## How it works

Windows tracks page faults per process through the working set watch API (`InitializeProcessForWsWatch` / `GetWsChangesEx`). Every time a page is brought into the working set, the OS records the instruction pointer (`FaultingPc`) that triggered the fault.

Faultline polls these events, checks whether each `FaultingPc` falls within a known loaded module, and flags execution from memory regions that are executable but not backed by any module in the PEB. When a suspicious fault is detected, the faulting thread is suspended and its stack is walked to capture the full call chain.

This catches code that was injected via manual mapping, shellcode injection, or similar techniques where the executable memory is never registered with the Windows loader.

```mermaid
flowchart LR
  subgraph Attacker["Attacker (external process)"]
    A1[Manual map DLL]
    A2[Write shellcode]
    A3[SetThreadContext]
    A4[APC injection]
  end

  subgraph Target["Target process"]
    B[Execution from\nunregistered memory]
    C[Page fault]
    D[OS records FaultingPc\nin working set buffer]
  end

  subgraph Faultline
    E[Poll GetWsChangesEx]
    F{FaultingPc in\nknown module?}
    G[Suspend thread\n+ stack walk]
    H[Flagged]
  end

  A1 --> B
  A2 --> B
  A3 --> B
  A4 --> B
  B --> C --> D --> E --> F
  F -- No --> G --> H
  F -- Yes --> I[Ignore]
```

## Catching thread hijacks from usermode

This also covers thread hijacking. If an external process redirects a thread via `SetThreadContext` / `NtSetContextThread`, APC injection, or similar into injected memory, the page fault still fires. The `FaultingPc` still lands outside any known module, and faultline catches it.

What's actually being detected is the side effect: execution from memory that isn't backed by a loaded module, not the redirection itself. There's no kernel callback for context changes, and ETW can trace the relevant syscalls but that's indirect at best. Faultline skips the interception problem entirely and just watches where threads end up executing. If it's unregistered memory and it faults a page, it's visible.

## Components

| Directory  | Description |
|------------|-------------|
| `anticheat/`  | Core detection DLL. Monitors working set faults, classifies memory regions, walks stacks |
| `host/`    | Minimal target process that loads the detection DLL |
| `injector/`| Manual mapper that injects the test payload into the host process |
| `payload/` | Test DLL that executes from manually mapped memory to trigger detection |
| `shared/`  | Common headers (logger, RAII handles, utilities) |

## Usage

1. Start `host.exe`
2. Run `injector.exe` in a separate terminal
3. The host console will log any detected suspicious execution along with stack traces

The injector supports two modes:

- **Remote thread** (default): `injector.exe` creates a new thread in the host via `CreateRemoteThread`
- **Thread hijack**: `injector.exe --hijack` redirects an existing host thread via `SetThreadContext`

Both trigger detection, but the host runs a background game loop thread that serves as the hijack target

## Demo

https://github.com/user-attachments/assets/333cd0b7-32e7-4dbb-8cbe-7b2b7125527e

## Limitations

- The working set watch API only fires on the first access to a page. Once a page is resident in the working set, further execution from it is invisible.
- Detection is reactive. By the time the fault is observed, the injected code has already run.
- Code caves or patches within legitimate modules will not be caught since the `FaultingPc` resolves to a known module range.
- The poll-based design means short lived threads may exit before a stack walk can be performed.
