#!/usr/bin/env python3
"""
Binary Reverse Engineering Toolkit
Purpose: Unpack, analyze, and understand binary executables
Use: Malware analysis, vulnerability research, software security
"""

import struct
import pefile
import hashlib
import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum
import capstone as cs
import lief

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BinaryType(Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    UNKNOWN = "unknown"

@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_data: bytes
    characteristics: int
    entropy: float

@dataclass
class ImportInfo:
    dll: str
    functions: List[str]

@dataclass
class ExportInfo:
    name: str
    address: int
    ordinal: int

class BinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.binary_data = self.load_binary()
        self.binary_type = self.detect_binary_type()
        self.analysis_results = {}
        
    def load_binary(self) -> bytes:
        """Load binary file into memory"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            raise
    
    def detect_binary_type(self) -> BinaryType:
        """Detect the type of binary file"""
        if len(self.binary_data) < 4:
            return BinaryType.UNKNOWN
        
        # Check for PE signature
        if self.binary_data[:2] == b'MZ':
            return BinaryType.PE
        # Check for ELF signature
        elif self.binary_data[:4] == b'\x7fELF':
            return BinaryType.ELF
        # Check for Mach-O signature
        elif self.binary_data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                                     b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return BinaryType.MACHO
        else:
            return BinaryType.UNKNOWN
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy
    
    def analyze_pe_file(self) -> Dict:
        """Analyze PE (Portable Executable) files"""
        logger.info("Analyzing PE file...")
        
        try:
            pe = pefile.PE(data=self.binary_data)
            analysis = {
                'file_info': self.extract_pe_file_info(pe),
                'sections': self.extract_pe_sections(pe),
                'imports': self.extract_pe_imports(pe),
                'exports': self.extract_pe_exports(pe),
                'resources': self.extract_pe_resources(pe),
                'security': self.extract_pe_security(pe)
            }
            return analysis
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return {}
    
    def extract_pe_file_info(self, pe) -> Dict:
        """Extract basic PE file information"""
        info = {
            'machine': hex(pe.FILE_HEADER.Machine),
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'characteristics': hex(pe.FILE_HEADER.Characteristics),
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            'size_of_image': pe.OPTIONAL_HEADER.SizeOfImage,
            'checksum': hex(pe.OPTIONAL_HEADER.CheckSum)
        }
        return info
    
    def extract_pe_sections(self, pe) -> List[SectionInfo]:
        """Extract PE section information"""
        sections = []
        for section in pe.sections:
            section_data = section.get_data()
            section_info = SectionInfo(
                name=section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_data=section_data,
                characteristics=section.Characteristics,
                entropy=self.calculate_entropy(section_data)
            )
            sections.append(section_info)
        return sections
    
    def extract_pe_imports(self, pe) -> List[ImportInfo]:
        """Extract PE import information"""
        imports = []
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode('utf-8', errors='ignore'))
                imports.append(ImportInfo(dll=dll_name, functions=functions))
        except AttributeError:
            logger.warning("No import table found")
        return imports
    
    def extract_pe_exports(self, pe) -> List[ExportInfo]:
        """Extract PE export information"""
        exports = []
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    export_name = exp.name.decode('utf-8', errors='ignore')
                    exports.append(ExportInfo(
                        name=export_name,
                        address=exp.address,
                        ordinal=exp.ordinal
                    ))
        except AttributeError:
            logger.warning("No export table found")
        return exports
    
    def extract_pe_resources(self, pe) -> Dict:
        """Extract PE resource information"""
        resources = {}
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'name'):
                    resource_name = str(resource_type.name)
                else:
                    resource_name = f"Type_{resource_type.id}"
                resources[resource_name] = len(resource_type.directory.entries)
        except AttributeError:
            logger.warning("No resources found")
        return resources
    
    def extract_pe_security(self, pe) -> Dict:
        """Extract PE security information"""
        security = {
            'aslr': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040),
            'dep': bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100),
            'authenticode': False,
            'checksum_valid': False
        }
        
        # Check digital signature
        try:
            security['authenticode'] = pe.verify_checksum()
            security['checksum_valid'] = security['authenticode']
        except:
            pass
        
        return security
    
    def analyze_elf_file(self) -> Dict:
        """Analyze ELF (Executable and Linkable Format) files"""
        logger.info("Analyzing ELF file...")
        
        try:
            binary = lief.parse(str(self.binary_path))
            if not binary:
                return {}
            
            analysis = {
                'file_info': self.extract_elf_file_info(binary),
                'sections': self.extract_elf_sections(binary),
                'segments': self.extract_elf_segments(binary),
                'symbols': self.extract_elf_symbols(binary),
                'dynamic_entries': self.extract_elf_dynamic_entries(binary)
            }
            return analysis
        except Exception as e:
            logger.error(f"ELF analysis failed: {e}")
            return {}
    
    def extract_elf_file_info(self, binary) -> Dict:
        """Extract basic ELF file information"""
        info = {
            'file_type': str(binary.header.file_type),
            'machine_type': str(binary.header.machine_type),
            'entry_point': hex(binary.header.entrypoint),
            'is_pie': binary.is_pie,
            'has_nx': binary.has_nx
        }
        return info
    
    def extract_elf_sections(self, binary) -> List[Dict]:
        """Extract ELF section information"""
        sections = []
        for section in binary.sections:
            section_data = bytes(section.content)
            section_info = {
                'name': section.name,
                'type': str(section.type),
                'flags': section.flags,
                'virtual_address': section.virtual_address,
                'size': section.size,
                'entropy': self.calculate_entropy(section_data)
            }
            sections.append(section_info)
        return sections
    
    def extract_elf_segments(self, binary) -> List[Dict]:
        """Extract ELF segment information"""
        segments = []
        for segment in binary.segments:
            segment_info = {
                'type': str(segment.type),
                'flags': segment.flags,
                'virtual_address': segment.virtual_address,
                'virtual_size': segment.virtual_size,
                'file_size': segment.physical_size
            }
            segments.append(segment_info)
        return segments
    
    def extract_elf_symbols(self, binary) -> List[Dict]:
        """Extract ELF symbol information"""
        symbols = []
        for symbol in binary.symbols:
            symbol_info = {
                'name': symbol.name,
                'value': symbol.value,
                'size': symbol.size,
                'type': str(symbol.type)
            }
            symbols.append(symbol_info)
        return symbols
    
    def extract_elf_dynamic_entries(self, binary) -> List[Dict]:
        """Extract ELF dynamic entries"""
        entries = []
        for entry in binary.dynamic_entries:
            entry_info = {
                'tag': str(entry.tag),
                'value': entry.value
            }
            entries.append(entry_info)
        return entries
    
    def disassemble_code(self, architecture: str = 'x86') -> List[Dict]:
        """Disassemble binary code sections"""
        logger.info(f"Disassembling code for {architecture}...")
        
        # Map architecture to Capstone constants
        arch_map = {
            'x86': (cs.CS_ARCH_X86, cs.CS_MODE_32),
            'x64': (cs.CS_ARCH_X86, cs.CS_MODE_64),
            'arm': (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
            'arm64': (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
        }
        
        if architecture not in arch_map:
            logger.error(f"Unsupported architecture: {architecture}")
            return []
        
        arch, mode = arch_map[architecture]
        md = cs.Cs(arch, mode)
        md.detail = True
        
        instructions = []
        
        # Find executable sections
        if self.binary_type == BinaryType.PE:
            try:
                pe = pefile.PE(data=self.binary_data)
                for section in pe.sections:
                    if section.Characteristics & 0x20000000:  # Executable
                        section_data = section.get_data()
                        code_offset = section.VirtualAddress
                        
                        for instruction in md.disasm(section_data, code_offset):
                            instructions.append({
                                'address': hex(instruction.address),
                                'size': instruction.size,
                                'bytes': instruction.bytes.hex(),
                                'mnemonic': instruction.mnemonic,
                                'op_str': instruction.op_str
                            })
            except Exception as e:
                logger.error(f"PE disassembly failed: {e}")
        
        return instructions[:1000]  # Limit output
    
    def detect_packing(self) -> Dict:
        """Detect if binary is packed and identify packer"""
        packer_indicators = {
            'UPX': [b'UPX!', b'UPX0', b'UPX1'],
            'ASPack': [b'ASPack'],
            'PECompact': [b'PEC2', b'PEC2.0'],
            'Themida': [b'Themida'],
            'VMProtect': [b'VMProtect'],
            'Armadillo': [b'Armadillo']
        }
        
        detection_results = {}
        binary_string = self.binary_data
        
        for packer, signatures in packer_indicators.items():
            for signature in signatures:
                if signature in binary_string:
                    detection_results[packer] = True
                    logger.info(f"Detected packer: {packer}")
                    break
        
        # Entropy-based packing detection
        high_entropy_sections = 0
        if self.binary_type == BinaryType.PE:
            try:
                pe = pefile.PE(data=self.binary_data)
                for section in pe.sections:
                    section_data = section.get_data()
                    entropy = self.calculate_entropy(section_data)
                    if entropy > 7.0:  # High entropy indicates possible packing
                        high_entropy_sections += 1
            except:
                pass
        
        detection_results['high_entropy_sections'] = high_entropy_sections
        detection_results['suspicious'] = high_entropy_sections > 1
        
        return detection_results
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary"""
        strings = []
        current_string = ""
        
        for byte in self.binary_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def calculate_hashes(self) -> Dict:
        """Calculate various hash digests of the binary"""
        return {
            'md5': hashlib.md5(self.binary_data).hexdigest(),
            'sha1': hashlib.sha1(self.binary_data).hexdigest(),
            'sha256': hashlib.sha256(self.binary_data).hexdigest(),
            'imphash': self.calculate_imphash() if self.binary_type == BinaryType.PE else 'N/A'
        }
    
    def calculate_imphash(self) -> str:
        """Calculate import hash for PE files"""
        try:
            pe = pefile.PE(data=self.binary_data)
            return pe.get_imphash()
        except:
            return "N/A"
    
    def comprehensive_analysis(self) -> Dict:
        """Perform comprehensive binary analysis"""
        logger.info("Starting comprehensive binary analysis...")
        
        analysis = {
            'file_info': {
                'filename': self.binary_path.name,
                'size': len(self.binary_data),
                'type': self.binary_type.value,
                'hashes': self.calculate_hashes()
            },
            'packing_analysis': self.detect_packing(),
            'strings': self.extract_strings()[:100],  # Limit string output
            'disassembly': []
        }
        
        # Architecture-specific analysis
        if self.binary_type == BinaryType.PE:
            pe_analysis = self.analyze_pe_file()
            analysis.update(pe_analysis)
            analysis['disassembly'] = self.disassemble_code('x86')
        elif self.binary_type == BinaryType.ELF:
            elf_analysis = self.analyze_elf_file()
            analysis.update(elf_analysis)
            analysis['disassembly'] = self.disassemble_code('x64')
        
        # Security assessment
        analysis['security_assessment'] = self.assess_security(analysis)
        
        return analysis
    
    def assess_security(self, analysis: Dict) -> Dict:
        """Assess binary security features"""
        security = {
            'risk_level': 'low',
            'warnings': [],
            'recommendations': []
        }
        
        # Packing detection
        if analysis['packing_analysis'].get('suspicious', False):
            security['warnings'].append('Binary appears to be packed')
            security['risk_level'] = 'medium'
        
        # Check for suspicious imports
        if 'imports' in analysis:
            suspicious_imports = [
                'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
                'CreateRemoteThread', 'SetWindowsHook', 'RegSetValue'
            ]
            
            for imp in analysis['imports']:
                for func in imp.functions:
                    if func in suspicious_imports:
                        security['warnings'].append(f'Suspicious import: {func}')
                        security['risk_level'] = 'high'
        
        # High entropy sections
        high_entropy_count = analysis['packing_analysis'].get('high_entropy_sections', 0)
        if high_entropy_count > 2:
            security['warnings'].append('Multiple high-entropy sections detected')
        
        # Recommendations
        if security['risk_level'] == 'high':
            security['recommendations'].extend([
                'Analyze in sandbox environment',
                'Monitor network activity',
                'Check for persistence mechanisms'
            ])
        elif security['risk_level'] == 'medium':
            security['recommendations'].extend([
                'Further static analysis recommended',
                'Behavioral analysis in controlled environment'
            ])
        
        return security

class Unpacker:
    """Tools for unpacking protected binaries"""
    
    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.binary_data = self.load_binary()
    
    def load_binary(self) -> bytes:
        """Load binary file"""
        with open(self.binary_path, 'rb') as f:
            return f.read()
    
    def upx_unpack(self, output_path: Optional[Path] = None) -> bool:
        """Attempt to unpack UPX-packed binary"""
        if not output_path:
            output_path = self.binary_path.with_suffix('.unpacked')
        
        try:
            import subprocess
            result = subprocess.run(
                ['upx', '-d', str(self.binary_path), '-o', str(output_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"UPX unpacking failed: {e}")
            return False
    
    def manual_unpack_pe(self) -> Dict:
        """Manual PE unpacking techniques"""
        logger.info("Attempting manual PE unpacking...")
        
        try:
            pe = pefile.PE(data=self.binary_data)
            unpacking_results = {
                'original_entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'sections_analyzed': []
            }
            
            # Look for OEP (Original Entry Point) patterns
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    'entropy': self.calculate_entropy(section.get_data()),
                    'is_executable': bool(section.Characteristics & 0x20000000)
                }
                unpacking_results['sections_analyzed'].append(section_info)
            
            return unpacking_results
        except Exception as e:
            logger.error(f"Manual unpacking failed: {e}")
            return {}
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Binary Reverse Engineering Toolkit')
    parser.add_argument('binary', help='Binary file to analyze')
    parser.add_argument('--analyze', action='store_true', help='Perform comprehensive analysis')
    parser.add_argument('--unpack', action='store_true', help='Attempt to unpack binary')
    parser.add_argument('--disassemble', help='Disassemble with architecture (x86, x64, arm, arm64)')
    parser.add_argument('--strings', action='store_true', help='Extract strings from binary')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    if not Path(args.binary).exists():
        print(f"Error: Binary file {args.binary} not found")
        return
    
    analyzer = BinaryAnalyzer(args.binary)
    
    try:
        if args.analyze:
            print(f"Analyzing binary: {args.binary}")
            results = analyzer.comprehensive_analysis()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Results saved to: {args.output}")
            else:
                print(json.dumps(results, indent=2))
        
        elif args.unpack:
            unpacker = Unpacker(args.binary)
            print("Attempting to unpack binary...")
            
            # Check for UPX
            packing_info = analyzer.detect_packing()
            if 'UPX' in packing_info and packing_info['UPX']:
                print("UPX packer detected, attempting unpack...")
                if unpacker.upx_unpack():
                    print("Successfully unpacked with UPX")
                else:
                    print("UPX unpacking failed")
            
            # Manual unpacking
            manual_results = unpacker.manual_unpack_pe()
            print("Manual unpacking analysis:")
            print(json.dumps(manual_results, indent=2))
        
        elif args.disassemble:
            instructions = analyzer.disassemble_code(args.disassemble)
            print(f"Disassembly results ({len(instructions)} instructions):")
            for instr in instructions[:50]:  # Show first 50 instructions
                print(f"{instr['address']}: {instr['mnemonic']} {instr['op_str']}")
        
        elif args.strings:
            strings = analyzer.extract_strings()
            print(f"Extracted {len(strings)} strings:")
            for string in strings[:50]:  # Show first 50 strings
                print(string)
        
        else:
            print("Binary Reverse Engineering Toolkit")
            print(f"File: {args.binary}")
            print(f"Type: {analyzer.binary_type.value}")
            print(f"Size: {len(analyzer.binary_data)} bytes")
            print("Use --help for available commands")
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")

if __name__ == "__main__":
    main()
