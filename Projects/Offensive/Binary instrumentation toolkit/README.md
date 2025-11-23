# Binary Instrumentation Toolkit

## What the Tool is For:
A comprehensive binary instrumentation framework for dynamic analysis, function hooking, process manipulation, and runtime monitoring. Enables security researchers to analyze and modify binary behavior without source code.

## About:
Binary instrumentation allows inserting analysis code into existing binaries to monitor execution, modify behavior, or extract runtime information. This toolkit provides both user-space and kernel-level instrumentation capabilities.

## General Algorithm:
```
1. Process Attachment & Analysis
   - Attach to target process
   - Parse PE/ELF headers
   - Enumerate loaded modules

2. Function Hooking
   - Find target functions
   - Create trampolines
   - Install hooks

3. Code Injection
   - Allocate remote memory
   - Write shellcode
   - Create remote threads

4. Runtime Monitoring
   - API call logging
   - Memory access tracking
   - Exception handling

5. Process Manipulation
   - Memory patching
   - Register modification
   - Thread control
```

## How to Run the Code:

### Python Version:
```bash
# Install required packages
pip install psutil

# Run the toolkit
python3 binary_instrumentation.py <PID> inject
python3 binary_instrumentation.py <PID> hook
python3 binary_instrumentation.py <PID> monitor
python3 binary_instrumentation.py <PID> all

# Example with notepad
python3 binary_instrumentation.py 1234 all
```

### C Version (Windows):
```bash
# Compile with Visual Studio or MinGW
gcc -o instrumentation.exe binary_instrumentation.c -lpsapi

# Run
./instrumentation.exe
```

## Example Usage Scenarios:

### 1. API Monitoring:
```python
# Monitor specific API calls
toolkit.monitor.start_api_monitoring(process_handle)

# Custom hook for CreateFileA
def file_create_hook(filename, access, mode):
    print(f"[MONITOR] File accessed: {filename}")
    return 0  # Allow the call
```

### 2. Code Injection:
```python
# Inject reflective DLL
shellcode = generate_reflective_dll(dll_bytes)
toolkit.instrumentation.inject_shellcode(process_handle, shellcode)
```

### 3. Function Hooking:
```python
# Hook network functions
toolkit.hook_manager.install_hook(
    process_handle, 
    "ws2_32.dll", 
    "connect", 
    network_connect_hook
)
```

## Key Features:

1. **Process Manipulation**: Attach, inject, and control processes
2. **Function Hooking**: Intercept and modify API calls
3. **Memory Operations**: Read, write, and protect memory regions
4. **Code Injection**: Execute custom code in target processes
5. **Runtime Monitoring**: Track API calls and system interactions
6. **Cross-Platform**: Windows implementation with Linux support structure

## Educational Value:

This toolkit teaches:
- Process internals and memory management
- Windows/Linux system APIs
- Dynamic binary instrumentation
- Malware analysis techniques
- Anti-debugging and anti-analysis methods
- Secure coding practices

**CRITICAL LEGAL NOTICE**: This tool is for authorized security research, penetration testing, and educational purposes ONLY. Never use against systems without explicit permission. Unauthorized process manipulation may violate laws and regulations.

## Common Instrumentation Techniques:

```c
// 1. IAT Hooking - Modify Import Address Table
PatchIAT("kernel32.dll", "CreateFileA", Hooked_CreateFileA);

// 2. EAT Hooking - Modify Export Address Table  
PatchEAT("target.dll", "ExportFunction", Hooked_ExportFunction);

// 3. Inline Hooking - Patch function prologue
InstallInlineHook(0x401000, Hook_Function);

// 4. VEH Hooking - Use Vectored Exception Handling
AddVectoredExceptionHandler(1, ExceptionHandler);
```
