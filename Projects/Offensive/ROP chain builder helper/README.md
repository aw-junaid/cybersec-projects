# ROP Chain Builder Helper

## What the Tool is For:
A educational tool to help understand and create Return-Oriented Programming (ROP) chains for x86/x64 architectures. Assists in gadget discovery, chain construction, and exploit development for authorized penetration testing and security research.

## About:
ROP is an advanced exploitation technique that uses existing code snippets (gadgets) in program memory to bypass DEP/NX protections. This tool helps identify useful gadgets and construct working ROP chains.

## General Algorithm:
```
1. Binary Analysis
   - Parse executable sections
   - Extract executable code segments
   - Identify potential gadgets

2. Gadget Discovery
   - Scan for useful instruction sequences
   - Filter by functionality (stack pivots, etc.)
   - Categorize by architecture (x86/x64)

3. Chain Construction
   - Build gadget sequences for specific tasks
   - Handle parameter passing
   - Manage stack alignment

4. Payload Generation
   - Create working exploit chains
   - Generate debug output
   - Produce final payload
```

## How to Run the Code:

### Python Version:
```bash
# Install dependencies
pip install capstone

# Analyze a binary for gadgets
python3 rop_builder.py vulnerable_binary

# Search for specific gadgets
python3 rop_builder.py vulnerable_binary --search "pop rdi" --category register_control

# Use predefined template
python3 rop_builder.py --template linux_execve

# Specify architecture
python3 rop_builder.py vulnerable_binary --arch x86 --base-address 0x08048000
```

### C Version:
```bash
# Compile
gcc -o rop_helper rop_builder.c

# Run
./rop_helper
```

## Example ROP Chain Construction:

### Linux x64 execve Chain:
```python
# Example generated chain
chain = [
    {
        'gadget': {
            'address': 0x401000,
            'instructions': ['pop rdi', 'ret'],
            'category': 'register_control'
        },
        'value': 0x402000,  # Address of "/bin/sh" string
        'description': 'Set RDI to /bin/sh string address'
    },
    {
        'gadget': {
            'address': 0x401010, 
            'instructions': ['pop rsi', 'ret'],
            'category': 'register_control'
        },
        'value': 0x0,  # NULL
        'description': 'Set RSI to NULL'
    },
    {
        'gadget': {
            'address': 0x401020,
            'instructions': ['pop rdx', 'ret'], 
            'category': 'register_control'
        },
        'value': 0x0,  # NULL
        'description': 'Set RDX to NULL'
    },
    {
        'gadget': {
            'address': 0x401030,
            'instructions': ['pop rax', 'ret'],
            'category': 'register_control' 
        },
        'value': 59,  # execve syscall number
        'description': 'Set RAX to 59 (execve)'
    },
    {
        'gadget': {
            'address': 0x401040,
            'instructions': ['syscall', 'ret'],
            'category': 'system_call'
        },
        'description': 'Execute syscall'
    }
]
```

## Key Features:

1. **Gadget Discovery**: Automated scanning for ROP gadgets
2. **Chain Construction**: Build working ROP chains for common tasks
3. **Architecture Support**: x86 and x64 architectures
4. **Educational Templates**: Pre-built chains for learning
5. **Analysis Tools**: Gadget categorization and filtering

## Educational Value:

This tool teaches:
- ROP exploitation fundamentals
- x86/x64 assembly and architecture
- Memory corruption techniques
- Exploit mitigation bypasses
- Binary analysis methods
- Secure coding practices

**IMPORTANT**: This tool is for authorized security research and education only. Never use against systems without explicit permission. ROP exploitation against unauthorized systems is illegal.

## Common ROP Gadget Patterns:

```c
// Essential gadget types for x64
pop_rax = find_gadget("pop rax; ret");
pop_rdi = find_gadget("pop rdi; ret"); 
pop_rsi = find_gadget("pop rsi; ret");
pop_rdx = find_gadget("pop rdx; ret");
syscall = find_gadget("syscall; ret");

// Stack pivoting
xchg_rsp_rax = find_gadget("xchg rsp, rax; ret");
mov_rsp_rbp = find_gadget("mov rsp, rbp; ret");

// Memory operations
mov_rdi_rsi = find_gadget("mov [rdi], rsi; ret");
```
