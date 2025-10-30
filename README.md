# VEH-Based Function Call Obfuscation

Obfuscating function calls using Vectored Exception Handlers by redirecting execution through exception-based control flow. Uses byte switching without memory or assembly allocation.

## Explanation

The implementation intercepts function calls by intentionally triggering CPU exceptions instead of using traditional jumps. When a protected function is called, Windows triggers a `STATUS_GUARD_PAGE_VIOLATION` exception. The Vectored Exception Handler catches this exception before normal execution continues, checks if the instruction pointer (RIP/EIP) matches a registered hook entry, and redirects execution to a hook function by modifying the CPU context.

For persistent hooking, a trap flag is set after redirection. This triggers a `STATUS_SINGLE_STEP` exception after one instruction executes, allowing the handler to automatically restore the PAGE_GUARD protection (since Windows clears it after each violation). This ensures the hook works on every subsequent call without manual intervention.

An alternative method uses `INT3` breakpoint instructions (byte switching - writing 0xCC) to trigger `STATUS_BREAKPOINT` exceptions for control flow obfuscation, hiding function calls and jumps behind exception handling logic.

**Key Point**: All operations use byte switching - modifying existing code bytes in-place using `vxmovememory()`. No memory allocation, no assembly generation required.

## Two Obfuscation Methods

### Guard Page Violation Method
Protects target function addresses with `PAGE_EXECUTE_READ | PAGE_GUARD` memory protection via `NtProtectVirtualMemory`. Each function call triggers a guard page violation exception, which the VEH handler intercepts to redirect execution. The handler modifies RIP/EIP bytes in the CPU context structure.

### INT3 Breakpoint Method  
Places `INT3` (0xCC) instruction at target addresses by switching the first byte to 0xCC. Execution hits the breakpoint, triggers `STATUS_BREAKPOINT`, and the handler redirects control flow to obfuscated paths. Uses `NtFlushInstructionCache` to flush CPU cache after byte modification.

## Using the VEH Obfuscation

- Example in ebytesyscalls.cpp

## Key Functions

- `vehhook::initialize()` - Registers the VEH exception handler with Windows
- `vehhook::addhook(entry)` - Adds hook entry and sets PAGE_GUARD protection via `NtProtectVirtualMemory`
- `vehhook::removehook(entry)` - Removes hook and restores memory protection
- `vehhook::findhook(address)` - Finds hook entry by original function address
- `vehhook::triggerint3hook(target, redirect, entry)` - Installs INT3 breakpoint (switches byte to 0xCC) for control flow obfuscation

## Implementation Details

The exception handler processes three exception types in order:

1. **STATUS_BREAKPOINT** - INT3 breakpoint hits, redirects execution by modifying RIP/EIP
2. **STATUS_GUARD_PAGE_VIOLATION** - Guard page accessed, redirects and sets trap flag (EFlags |= 0x100)
3. **STATUS_SINGLE_STEP** - Trap flag triggered, restores PAGE_GUARD for all hooks via `NtProtectVirtualMemory`

**Important Notes**:
- Memory protection changes use `NtProtectVirtualMemory` via `internals::getprocaddr()` - this is **NOT a direct syscall**, it's the Nt* API resolved dynamically
- Function addresses are resolved through manual PE parsing via `internals::getprocaddr()` instead of `GetProcAddress()`
- All byte modifications use `vxmovememory()` - no standard library memory functions
- INT3 installation uses byte switching (writes 0xCC) then flushes instruction cache via `NtFlushInstructionCache`

## Byte Switching Approach

Unlike traditional hooking that allocates memory or generates assembly:
- Guard page method: Only modifies memory protection flags (no code bytes changed)
- INT3 method: Switches one byte (0xCC) in-place, no allocation needed
- Both methods: Redirect execution via CPU context modification (RIP/EIP), not code patching
- Exception handlers: Modify existing CPU register state, no new memory required

## Notes

The VEH obfuscation technique works by leveraging Windows exception handling infrastructure. Control flow redirection happens in the exception handler, making static analysis more difficult since execution jumps aren't visible in the original code.

You can combine both methods - use guard page hooks for function interception and INT3 breakpoints for general control flow obfuscation throughout your code.

All operations use byte switching - modifying existing code or CPU state without allocating new memory or generating assembly instructions.

## Disclaimer

This implementation demonstrates exception-based control flow obfuscation. The technique hides execution flow in exception handlers but can be detected through VEH enumeration, exception frequency analysis, or advanced EDR monitoring. Use as one layer of a multi-layered obfuscation strategy.

# License
- MIT


# Credits 
- AdvDebug for hook -> copymem. (github.com/AdvDebug)
