#!/usr/bin/env python3
import numpy as np
import random
import time
import threading
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class FaultType(Enum):
    VOLTAGE_GLITCH = 1
    CLOCK_GLITCH = 2
    EM_PULSE = 3
    LASER_FAULT = 4
    TEMPERATURE = 5
    RADIATION = 6

class DeviceArchitecture(Enum):
    ARM_CORTEX_M = 1
    AVR = 2
    PIC = 3
    RISC_V = 4
    X86 = 5

@dataclass
class FaultParameters:
    fault_type: FaultType
    intensity: float  # 0.0 to 1.0
    duration: float   # nanoseconds
    timing: float     # nanoseconds from trigger
    location: tuple   # (x, y) coordinates for spatial faults

class HardwareFaultLab:
    def __init__(self, architecture: DeviceArchitecture = DeviceArchitecture.ARM_CORTEX_M):
        self.architecture = architecture
        self.fault_injections = []
        self.fault_results = []
        self.device_state = {}
        self.crypto_keys = {}
        
        # Initialize device simulation
        self.setup_device_simulation()
        
        # Fault injection parameters
        self.fault_success_rates = {
            FaultType.VOLTAGE_GLITCH: 0.3,
            FaultType.CLOCK_GLITCH: 0.4,
            FaultType.EM_PULSE: 0.25,
            FaultType.LASER_FAULT: 0.6,
            FaultType.TEMPERATURE: 0.15,
            FaultType.RADIATION: 0.2
        }
        
        print(f"[+] Hardware Fault Injection Lab Initialized")
        print(f"    Architecture: {architecture.name}")
        print(f"    Ready for fault injection experiments")
    
    def setup_device_simulation(self):
        """Initialize simulated device components"""
        self.device_state = {
            'registers': {
                'R0': 0x00000000, 'R1': 0x00000000, 'R2': 0x00000000, 'R3': 0x00000000,
                'R4': 0x00000000, 'R5': 0x00000000, 'R6': 0x00000000, 'R7': 0x00000000,
                'PC': 0x00000000, 'SP': 0x20001000, 'LR': 0x00000000, 'PSR': 0x01000000
            },
            'memory': np.zeros(1024, dtype=np.uint8),  # 1KB RAM
            'flash': np.zeros(8192, dtype=np.uint8),   # 8KB Flash
            'peripherals': {
                'GPIOA': 0x0000,
                'GPIOB': 0x0000,
                'UART': 0x0000,
                'SPI': 0x0000,
                'I2C': 0x0000
            },
            'security_registers': {
                'READ_PROTECT': 0x00,
                'WRITE_PROTECT': 0x00,
                'CRYPTO_KEY': bytearray(32),
                'CHIP_ID': bytearray(16)
            }
        }
        
        # Initialize with some test data
        self._initialize_test_data()
    
    def _initialize_test_data(self):
        """Initialize device with test data and keys"""
        # Load AES key
        self.crypto_keys['aes_key'] = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
        
        # Load test firmware
        firmware = self._generate_test_firmware()
        self.device_state['flash'][:len(firmware)] = firmware
        
        # Set chip ID
        chip_id = hashlib.md5(b"test_device_123").digest()
        self.device_state['security_registers']['CHIP_ID'] = bytearray(chip_id)
    
    def _generate_test_firmware(self) -> np.ndarray:
        """Generate simple test firmware for simulation"""
        # Simple ARM Thumb instructions for testing
        firmware_bytes = [
            0x00, 0x20, 0x01, 0x21,  # MOVS R0, #0; MOVS R1, #1
            0x02, 0x22, 0x03, 0x23,  # MOVS R2, #2; MOVS R3, #3
            0x88, 0x42,              # CMP R0, R1
            0x01, 0xD1,              # BNE +2
            0x00, 0xBF,              # NOP
            0xFE, 0xE7               # B -4 (infinite loop)
        ]
        return np.array(firmware_bytes, dtype=np.uint8)
    
    def simulate_normal_operation(self, cycles: int = 1000) -> Dict[str, Any]:
        """Simulate normal device operation"""
        print(f"[*] Simulating {cycles} cycles of normal operation")
        
        results = {
            'registers_changes': [],
            'memory_accesses': [],
            'instructions_executed': 0,
            'power_consumption': [],
            'timing_characteristics': []
        }
        
        # Simple CPU simulation
        pc = self.device_state['registers']['PC']
        for cycle in range(cycles):
            if pc >= len(self.device_state['flash']) - 2:
                pc = 0  # Reset to start
            
            # Fetch instruction (2 bytes for Thumb)
            instruction = (self.device_state['flash'][pc] << 8) | self.device_state['flash'][pc + 1]
            
            # Simple instruction decode and execute
            opcode = (instruction >> 10) & 0x3F
            rd = (instruction >> 8) & 0x07
            imm8 = instruction & 0xFF
            
            if opcode == 0b000111:  # MOVS Rd, #imm8
                self.device_state['registers'][f'R{rd}'] = imm8
                results['registers_changes'].append((f'R{rd}', imm8))
            
            pc += 2
            self.device_state['registers']['PC'] = pc
            results['instructions_executed'] += 1
            
            # Simulate power consumption
            power = random.uniform(10.0, 15.0)  # mA
            results['power_consumption'].append(power)
        
        return results
    
    def inject_fault(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Inject a fault into the simulated device"""
        print(f"[*] Injecting {fault_params.fault_type.name} fault")
        print(f"    Intensity: {fault_params.intensity:.2f}, Duration: {fault_params.duration}ns")
        
        self.fault_injections.append(fault_params)
        
        # Calculate success probability
        base_rate = self.fault_success_rates[fault_params.fault_type]
        success_prob = base_rate * fault_params.intensity
        
        fault_successful = random.random() < success_prob
        fault_effect = self._simulate_fault_effect(fault_params, fault_successful)
        
        result = {
            'fault_params': fault_params,
            'successful': fault_successful,
            'effects': fault_effect,
            'device_state_before': self._snapshot_device_state(),
            'device_state_after': None
        }
        
        if fault_successful:
            self._apply_fault_effects(fault_effect)
            result['device_state_after'] = self._snapshot_device_state()
        
        self.fault_results.append(result)
        return result
    
    def _simulate_fault_effect(self, fault_params: FaultParameters, successful: bool) -> Dict[str, Any]:
        """Simulate the effects of a successful fault injection"""
        if not successful:
            return {'type': 'NO_EFFECT', 'description': 'Fault injection failed'}
        
        effects = {}
        
        if fault_params.fault_type == FaultType.VOLTAGE_GLITCH:
            effects = self._simulate_voltage_glitch(fault_params)
        elif fault_params.fault_type == FaultType.CLOCK_GLITCH:
            effects = self._simulate_clock_glitch(fault_params)
        elif fault_params.fault_type == FaultType.EM_PULSE:
            effects = self._simulate_em_pulse(fault_params)
        elif fault_params.fault_type == FaultType.LASER_FAULT:
            effects = self._simulate_laser_fault(fault_params)
        elif fault_params.fault_type == FaultType.TEMPERATURE:
            effects = self._simulate_temperature_fault(fault_params)
        elif fault_params.fault_type == FaultType.RADIATION:
            effects = self._simulate_radiation_fault(fault_params)
        
        return effects
    
    def _simulate_voltage_glitch(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate voltage glitching effects"""
        effects = {'type': 'VOLTAGE_GLITCH'}
        
        # Randomly choose effect based on intensity
        effect_choice = random.random()
        
        if effect_choice < 0.3:
            # Instruction skip
            effects['subtype'] = 'INSTRUCTION_SKIP'
            effects['description'] = 'CPU skipped one or more instructions'
            effects['pc_skip'] = random.randint(2, 8)
            
        elif effect_choice < 0.6:
            # Register corruption
            reg = f'R{random.randint(0, 7)}'
            old_value = self.device_state['registers'][reg]
            new_value = old_value ^ random.getrandbits(32)
            effects['subtype'] = 'REGISTER_CORRUPTION'
            effects['description'] = f'Register {reg} corrupted'
            effects['register'] = reg
            effects['old_value'] = old_value
            effects['new_value'] = new_value
            
        else:
            # Memory corruption
            addr = random.randint(0, len(self.device_state['memory']) - 1)
            old_value = self.device_state['memory'][addr]
            new_value = old_value ^ random.getrandbits(8)
            effects['subtype'] = 'MEMORY_CORRUPTION'
            effects['description'] = f'Memory address {addr:04X} corrupted'
            effects['address'] = addr
            effects['old_value'] = old_value
            effects['new_value'] = new_value
        
        return effects
    
    def _simulate_clock_glitch(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate clock glitching effects"""
        effects = {'type': 'CLOCK_GLITCH'}
        
        effect_choice = random.random()
        
        if effect_choice < 0.4:
            # Timing violation - incorrect instruction execution
            effects['subtype'] = 'TIMING_VIOLATION'
            effects['description'] = 'Clock glitch caused timing violation'
            effects['instruction_corruption'] = True
            
        elif effect_choice < 0.7:
            # Pipeline stall
            effects['subtype'] = 'PIPELINE_STALL'
            effects['description'] = 'Clock glitch caused pipeline stall'
            effects['stall_cycles'] = random.randint(1, 5)
            
        else:
            # Security bypass
            effects['subtype'] = 'SECURITY_BYPASS'
            effects['description'] = 'Clock glitch bypassed security check'
            effects['protection_disabled'] = True
        
        return effects
    
    def _simulate_em_pulse(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate electromagnetic pulse effects"""
        effects = {'type': 'EM_PULSE'}
        
        # EM pulses often affect larger areas
        num_effects = random.randint(1, 3)
        effects['multiple_effects'] = []
        
        for _ in range(num_effects):
            effect_type = random.choice(['MEMORY_CORRUPTION', 'REGISTER_CORRUPTION', 'PERIPHERAL_GLITCH'])
            
            if effect_type == 'MEMORY_CORRUPTION':
                addr = random.randint(0, len(self.device_state['memory']) - 1)
                old_val = self.device_state['memory'][addr]
                new_val = old_val ^ random.getrandbits(8)
                effects['multiple_effects'].append({
                    'type': 'MEMORY_CORRUPTION',
                    'address': addr,
                    'old_value': old_val,
                    'new_value': new_val
                })
                
            elif effect_type == 'REGISTER_CORRUPTION':
                reg = f'R{random.randint(0, 7)}'
                old_val = self.device_state['registers'][reg]
                new_val = old_val ^ random.getrandbits(32)
                effects['multiple_effects'].append({
                    'type': 'REGISTER_CORRUPTION',
                    'register': reg,
                    'old_value': old_val,
                    'new_value': new_val
                })
        
        effects['description'] = f'EM pulse caused {num_effects} corruption(s)'
        return effects
    
    def _simulate_laser_fault(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate laser fault injection effects"""
        effects = {'type': 'LASER_FAULT'}
        
        # Laser faults are precise - target specific locations
        if fault_params.location:
            x, y = fault_params.location
            effects['target_location'] = (x, y)
            
            # High probability of successful precise fault
            if random.random() < 0.8:
                effects['subtype'] = 'BIT_FLIP'
                effects['description'] = f'Laser induced bit flip at location ({x}, {y})'
                
                # Target specific security registers
                if random.random() < 0.6:
                    # Corrupt security register
                    sec_reg = random.choice(list(self.device_state['security_registers'].keys()))
                    if sec_reg == 'READ_PROTECT':
                        old_val = self.device_state['security_registers'][sec_reg]
                        new_val = 0x00  # Disable read protection
                        effects['security_effect'] = 'READ_PROTECTION_DISABLED'
                        effects['register'] = sec_reg
                        effects['old_value'] = old_val
                        effects['new_value'] = new_val
        
        return effects
    
    def _simulate_temperature_fault(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate temperature-induced faults"""
        effects = {'type': 'TEMPERATURE_FAULT'}
        effects['subtype'] = 'TIMING_DEGRADATION'
        effects['description'] = 'Temperature variation caused timing degradation'
        effects['timing_slowdown'] = random.uniform(1.1, 2.0)  # 10-100% slowdown
        return effects
    
    def _simulate_radiation_fault(self, fault_params: FaultParameters) -> Dict[str, Any]:
        """Simulate radiation-induced faults"""
        effects = {'type': 'RADIATION_FAULT'}
        effects['subtype'] = 'RANDOM_BIT_FLIPS'
        effects['description'] = 'Radiation caused random bit flips throughout device'
        
        # Multiple random bit flips
        num_flips = random.randint(1, 5)
        effects['bit_flips'] = []
        
        for _ in range(num_flips):
            target_type = random.choice(['MEMORY', 'REGISTER'])
            if target_type == 'MEMORY':
                addr = random.randint(0, len(self.device_state['memory']) - 1)
                bit_pos = random.randint(0, 7)
                effects['bit_flips'].append({
                    'type': 'MEMORY',
                    'address': addr,
                    'bit_position': bit_pos
                })
            else:
                reg = f'R{random.randint(0, 7)}'
                bit_pos = random.randint(0, 31)
                effects['bit_flips'].append({
                    'type': 'REGISTER',
                    'register': reg,
                    'bit_position': bit_pos
                })
        
        return effects
    
    def _apply_fault_effects(self, effects: Dict[str, Any]):
        """Apply the simulated fault effects to device state"""
        if effects['type'] == 'VOLTAGE_GLITCH':
            if effects['subtype'] == 'REGISTER_CORRUPTION':
                reg = effects['register']
                self.device_state['registers'][reg] = effects['new_value']
            elif effects['subtype'] == 'MEMORY_CORRUPTION':
                addr = effects['address']
                self.device_state['memory'][addr] = effects['new_value']
                
        elif effects['type'] == 'LASER_FAULT':
            if 'security_effect' in effects:
                reg = effects['register']
                self.device_state['security_registers'][reg] = effects['new_value']
    
    def _snapshot_device_state(self) -> Dict[str, Any]:
        """Create a snapshot of current device state"""
        return {
            'registers': self.device_state['registers'].copy(),
            'memory': self.device_state['memory'].copy(),
            'security_registers': {
                k: v.copy() if isinstance(v, bytearray) else v
                for k, v in self.device_state['security_registers'].items()
            }
        }
    
    def perform_differential_fault_analysis(self, plaintext: bytes, num_faults: int = 100) -> Dict[str, Any]:
        """Perform differential fault analysis on AES encryption"""
        print(f"[*] Performing Differential Fault Analysis on AES")
        print(f"    Target: Extract AES key using {num_faults} fault injections")
        
        results = {
            'successful_faults': 0,
            'key_candidates': [],
            'fault_locations': [],
            'analysis_results': {}
        }
        
        cipher = Cipher(algorithms.AES(self.crypto_keys['aes_key']), modes.ECB(), backend=default_backend())
        
        for i in range(num_faults):
            # Encrypt normally
            encryptor = cipher.encryptor()
            normal_ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Inject fault during encryption
            fault_params = FaultParameters(
                fault_type=random.choice([FaultType.VOLTAGE_GLITCH, FaultType.CLOCK_GLITCH]),
                intensity=random.uniform(0.7, 1.0),
                duration=random.uniform(1.0, 10.0),
                timing=random.uniform(0.0, 100.0),
                location=None
            )
            
            fault_result = self.inject_fault(fault_params)
            
            if fault_result['successful']:
                results['successful_faults'] += 1
                
                # Simulate faulty encryption
                faulty_ciphertext = self._simulate_faulty_aes(plaintext, fault_params)
                
                # Analyze differential
                key_candidate = self._analyze_differential(normal_ciphertext, faulty_ciphertext)
                if key_candidate:
                    results['key_candidates'].append(key_candidate)
                    results['fault_locations'].append(i)
        
        # Statistical analysis
        if results['key_candidates']:
            results['analysis_results'] = self._statistical_key_analysis(results['key_candidates'])
        
        return results
    
    def _simulate_faulty_aes(self, plaintext: bytes, fault_params: FaultParameters) -> bytes:
        """Simulate AES encryption with injected fault"""
        # Simplified fault model - corrupt one byte in round 9
        cipher = Cipher(algorithms.AES(self.crypto_keys['aes_key']), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = bytearray(encryptor.update(plaintext) + encryptor.finalize())
        
        # Inject single byte fault
        fault_byte = random.randint(0, len(ciphertext) - 1)
        fault_bit = random.randint(0, 7)
        ciphertext[fault_byte] ^= (1 << fault_bit)
        
        return bytes(ciphertext)
    
    def _analyze_differential(self, normal_ct: bytes, faulty_ct: bytes) -> Optional[bytes]:
        """Analyze differential between normal and faulty ciphertexts"""
        differences = []
        for i, (n, f) in enumerate(zip(normal_ct, faulty_ct)):
            if n != f:
                differences.append((i, n ^ f))
        
        if len(differences) == 1:
            # Single byte fault - useful for DFA
            pos, diff = differences[0]
            return bytes([pos, diff])
        
        return None
    
    def _statistical_key_analysis(self, key_candidates: List[bytes]) -> Dict[str, Any]:
        """Perform statistical analysis on key candidates"""
        if not key_candidates:
            return {}
        
        # Count frequency of each candidate
        candidate_counts = {}
        for candidate in key_candidates:
            candidate_counts[candidate] = candidate_counts.get(candidate, 0) + 1
        
        # Find most likely candidates
        sorted_candidates = sorted(candidate_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_candidates': len(key_candidates),
            'unique_candidates': len(candidate_counts),
            'most_likely': sorted_candidates[:5],
            'confidence': sorted_candidates[0][1] / len(key_candidates) if key_candidates else 0
        }
    
    def visualize_fault_injections(self):
        """Create visualization of fault injection results"""
        if not self.fault_results:
            print("[-] No fault injection results to visualize")
            return
        
        # Prepare data for plotting
        fault_types = []
        success_rates = []
        intensities = []
        
        for fault_type in FaultType:
            type_results = [r for r in self.fault_results 
                          if r['fault_params'].fault_type == fault_type]
            if type_results:
                successful = sum(1 for r in type_results if r['successful'])
                success_rate = successful / len(type_results)
                avg_intensity = np.mean([r['fault_params'].intensity for r in type_results])
                
                fault_types.append(fault_type.name)
                success_rates.append(success_rate * 100)
                intensities.append(avg_intensity * 100)
        
        # Create plots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Success rates
        bars1 = ax1.bar(fault_types, success_rates, color='skyblue', alpha=0.7)
        ax1.set_title('Fault Injection Success Rates')
        ax1.set_ylabel('Success Rate (%)')
        ax1.set_xticklabels(fault_types, rotation=45)
        
        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%', ha='center', va='bottom')
        
        # Intensities
        bars2 = ax2.bar(fault_types, intensities, color='lightcoral', alpha=0.7)
        ax2.set_title('Average Fault Intensities')
        ax2.set_ylabel('Intensity (%)')
        ax2.set_xticklabels(fault_types, rotation=45)
        
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('fault_injection_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate comprehensive security assessment report"""
        report = {
            'timestamp': time.time(),
            'architecture': self.architecture.name,
            'total_fault_injections': len(self.fault_injections),
            'successful_injections': sum(1 for r in self.fault_results if r['successful']),
            'vulnerability_assessment': {},
            'recommendations': []
        }
        
        # Analyze vulnerabilities
        vuln_analysis = {}
        for result in self.fault_results:
            if result['successful']:
                fault_type = result['fault_params'].fault_type.name
                effects = result['effects']
                
                if fault_type not in vuln_analysis:
                    vuln_analysis[fault_type] = {'count': 0, 'effects': []}
                
                vuln_analysis[fault_type]['count'] += 1
                vuln_analysis[fault_type]['effects'].append(effects.get('subtype', 'UNKNOWN'))
        
        report['vulnerability_assessment'] = vuln_analysis
        
        # Generate recommendations
        if any('SECURITY_BYPASS' in str(effects) for results in vuln_analysis.values() 
               for effects in results.get('effects', [])):
            report['recommendations'].append(
                "Implement redundant security checks with temporal diversity"
            )
        
        if any('REGISTER_CORRUPTION' in str(effects) for results in vuln_analysis.values() 
               for effects in results.get('effects', [])):
            report['recommendations'].append(
                "Add register integrity checks and error-correcting codes"
            )
        
        if any('MEMORY_CORRUPTION' in str(effects) for results in vuln_analysis.values() 
               for effects in results.get('effects', [])):
            report['recommendations'].append(
                "Implement memory protection units and checksum verification"
            )
        
        # Always include general recommendations
        report['recommendations'].extend([
            "Use voltage and frequency monitors to detect fault injection attempts",
            "Implement sensor-based countermeasures (temperature, light, EM)",
            "Add redundancy in critical security operations",
            "Use randomized execution timing to complicate fault timing"
        ])
        
        return report

def main():
    """Demo the hardware fault injection lab"""
    print("Hardware Fault Injection Lab Demonstration")
    print("=========================================")
    
    # Initialize lab
    lab = HardwareFaultLab(DeviceArchitecture.ARM_CORTEX_M)
    
    # Simulate normal operation
    normal_results = lab.simulate_normal_operation(500)
    print(f"[+] Normal operation: {normal_results['instructions_executed']} instructions executed")
    
    # Perform various fault injections
    fault_types = [
        FaultType.VOLTAGE_GLITCH,
        FaultType.CLOCK_GLITCH, 
        FaultType.EM_PULSE,
        FaultType.LASER_FAULT
    ]
    
    print("\n[*] Performing fault injection experiments...")
    
    for fault_type in fault_types:
        for intensity in [0.3, 0.6, 0.9]:
            params = FaultParameters(
                fault_type=fault_type,
                intensity=intensity,
                duration=5.0,
                timing=50.0,
                location=(random.randint(0, 100), random.randint(0, 100)) if fault_type == FaultType.LASER_FAULT else None
            )
            
            result = lab.inject_fault(params)
            status = "SUCCESS" if result['successful'] else "FAILED"
            print(f"    {fault_type.name} (intensity {intensity}): {status}")
    
    # Perform Differential Fault Analysis
    print("\n[*] Performing Differential Fault Analysis...")
    dfa_results = lab.perform_differential_fault_analysis(b"test_plaintext_16b", 50)
    print(f"    Successful faults: {dfa_results['successful_faults']}/50")
    if dfa_results['analysis_results']:
        conf = dfa_results['analysis_results']['confidence'] * 100
        print(f"    Key extraction confidence: {conf:.1f}%")
    
    # Generate reports and visualizations
    print("\n[*] Generating security report...")
    report = lab.generate_security_report()
    print(f"    Total injections: {report['total_fault_injections']}")
    print(f"    Successful: {report['successful_injections']}")
    print(f"    Recommendations: {len(report['recommendations'])}")
    
    # Visualize results
    print("\n[*] Creating visualizations...")
    lab.visualize_fault_injections()
    
    print("\n[+] Demonstration complete!")
    print("    Check 'fault_injection_analysis.png' for results visualization")

if __name__ == "__main__":
    main()
