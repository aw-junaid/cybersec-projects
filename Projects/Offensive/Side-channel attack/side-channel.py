#!/usr/bin/env python3
"""
Side-Channel Attack Experiments - Educational Research Tool
Purpose: Study timing attacks, power analysis, and other side-channel vulnerabilities
Use: Cryptographic research, security testing, vulnerability assessment
"""

import time
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import statistics
import secrets
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import threading
from concurrent.futures import ThreadPoolExecutor
import psutil
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('side_channel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AttackType(Enum):
    TIMING_ATTACK = "timing_attack"
    CACHE_ATTACK = "cache_attack"
    POWER_ANALYSIS = "power_analysis"
    ELECTROMAGNETIC = "electromagnetic"
    ACOUSTIC = "acoustic"

@dataclass
class TimingMeasurement:
    input_data: bytes
    execution_time: float
    attempt: int
    additional_info: Dict

@dataclass
class AnalysisResult:
    attack_type: AttackType
    measurements: List[TimingMeasurement]
    statistics: Dict
    correlation_results: Dict
    vulnerability_assessment: Dict

class SideChannelAnalyzer:
    """Main class for side-channel attack experiments"""
    
    def __init__(self):
        self.measurements = []
        self.sample_size = 1000
        self.warmup_iterations = 100
        
    def insecure_string_comparison(self, input_str: str, secret: str) -> bool:
        """
        Insecure string comparison that leaks timing information
        Early returns when characters don't match
        """
        if len(input_str) != len(secret):
            return False
            
        for i in range(len(secret)):
            if input_str[i] != secret[i]:
                return False
        return True
    
    def secure_string_comparison(self, input_str: str, secret: str) -> bool:
        """
        Secure string comparison using constant-time algorithm
        """
        if len(input_str) != len(secret):
            # Still need to compare all characters to maintain constant time
            # Compare with a dummy string of same length
            dummy = 'x' * len(input_str)
            result = True
            for i in range(len(input_str)):
                if input_str[i] != dummy[i % len(dummy)]:
                    result = False
            return False
            
        result = True
        for i in range(len(secret)):
            if input_str[i] != secret[i]:
                result = False
        return result
    
    def measure_execution_time(self, func: Callable, *args, **kwargs) -> float:
        """Measure execution time of a function with high precision"""
        start_time = time.perf_counter_ns()
        result = func(*args, **kwargs)
        end_time = time.perf_counter_ns()
        execution_time = (end_time - start_time) / 1e6  # Convert to milliseconds
        return execution_time, result
    
    def timing_attack_on_string_comparison(self, secret: str, max_length: int = 10) -> str:
        """
        Demonstrate timing attack on string comparison
        Returns: Recovered secret string
        """
        logger.info(f"Starting timing attack on secret: {secret}")
        
        recovered = ""
        attempts_per_char = 200
        
        for position in range(max_length):
            logger.info(f"Analyzing character at position {position}")
            timings = {}
            
            # Test all possible characters at current position
            for char_code in range(32, 127):  # Printable ASCII
                char = chr(char_code)
                test_string = recovered + char + 'x' * (max_length - position - 1)
                
                times = []
                for _ in range(attempts_per_char):
                    execution_time, _ = self.measure_execution_time(
                        self.insecure_string_comparison, test_string, secret
                    )
                    times.append(execution_time)
                
                avg_time = statistics.mean(times)
                timings[char] = avg_time
            
            # Character with highest timing is likely correct
            likely_char = max(timings.items(), key=lambda x: x[1])[0]
            recovered += likely_char
            
            logger.info(f"Position {position}: likely character '{likely_char}'")
            
            # Check if we've found the complete secret
            if self.insecure_string_comparison(recovered, secret):
                logger.info(f"Secret recovered: {recovered}")
                break
        
        return recovered
    
    def simulate_power_consumption(self, data: bytes, operation: str = "AES") -> float:
        """
        Simulate power consumption based on Hamming weight of data
        In real hardware, this would correlate with actual power usage
        """
        if operation == "AES":
            # Simulate AES power consumption pattern
            hamming_weight = bin(int.from_bytes(data, 'big')).count('1')
            # Add some noise to simulate real conditions
            noise = np.random.normal(0, 0.1)
            return hamming_weight / 8 + noise  # Normalize to 0-1 range
        elif operation == "SHA256":
            # Simulate hash function power consumption
            intermediate_hash = hashlib.sha256(data).digest()
            hw = bin(int.from_bytes(intermediate_hash[:4], 'big')).count('1')
            return hw / 32 + np.random.normal(0, 0.05)
        else:
            return np.random.random()
    
    def simple_aes_operation(self, data: bytes, key: bytes) -> bytes:
        """Perform a simple AES operation for side-channel analysis"""
        if len(key) not in [16, 24, 32]:
            key = key.ljust(32, b'\0')[:32]
        
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        block_size = 16
        padded_data = data.ljust(block_size, b'\0')
        
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def collect_timing_measurements(self, target_function: Callable, 
                                  input_generator: Callable, 
                                  num_samples: int = 1000) -> List[TimingMeasurement]:
        """Collect timing measurements for analysis"""
        measurements = []
        
        logger.info(f"Collecting {num_samples} timing measurements...")
        
        for i in range(num_samples):
            input_data = input_generator()
            execution_time, result = self.measure_execution_time(target_function, input_data)
            
            measurement = TimingMeasurement(
                input_data=input_data,
                execution_time=execution_time,
                attempt=i,
                additional_info={'result': result}
            )
            measurements.append(measurement)
            
            if i % 100 == 0:
                logger.info(f"Collected {i}/{num_samples} measurements")
        
        return measurements
    
    def analyze_timing_data(self, measurements: List[TimingMeasurement]) -> AnalysisResult:
        """Analyze collected timing data for vulnerabilities"""
        times = [m.execution_time for m in measurements]
        
        stats = {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'stdev': statistics.stdev(times) if len(times) > 1 else 0,
            'min': min(times),
            'max': max(times),
            'variance': statistics.variance(times) if len(times) > 1 else 0
        }
        
        # Detect timing variations that could be exploited
        threshold = stats['stdev'] * 2
        significant_variations = [t for t in times if abs(t - stats['mean']) > threshold]
        
        vulnerability = {
            'has_timing_leak': len(significant_variations) > len(times) * 0.05,
            'variation_count': len(significant_variations),
            'max_variation': max([abs(t - stats['mean']) for t in times]) if times else 0,
            'confidence': min(100, len(significant_variations) / len(times) * 1000)
        }
        
        # Correlation analysis
        correlation_results = self.correlate_with_input(measurements)
        
        return AnalysisResult(
            attack_type=AttackType.TIMING_ATTACK,
            measurements=measurements,
            statistics=stats,
            correlation_results=correlation_results,
            vulnerability_assessment=vulnerability
        )
    
    def correlate_with_input(self, measurements: List[TimingMeasurement]) -> Dict:
        """Correlate timing with input characteristics"""
        if not measurements:
            return {}
        
        # Example: correlate with input length
        input_lengths = [len(m.input_data) for m in measurements]
        times = [m.execution_time for m in measurements]
        
        if len(input_lengths) > 1:
            length_correlation = np.corrcoef(input_lengths, times)[0, 1]
        else:
            length_correlation = 0
        
        # Correlate with Hamming weight
        hamming_weights = [bin(int.from_bytes(m.input_data, 'big')).count('1') 
                          for m in measurements if m.input_data]
        if hamming_weights and len(hamming_weights) > 1:
            hamming_correlation = np.corrcoef(hamming_weights, times[:len(hamming_weights)])[0, 1]
        else:
            hamming_correlation = 0
        
        return {
            'length_correlation': length_correlation,
            'hamming_weight_correlation': hamming_correlation,
            'significant_correlation': abs(length_correlation) > 0.3 or abs(hamming_correlation) > 0.3
        }
    
    def plot_timing_distribution(self, analysis_result: AnalysisResult, save_path: str = None):
        """Plot timing distribution analysis"""
        times = [m.execution_time for m in analysis_result.measurements]
        
        plt.figure(figsize=(12, 8))
        
        # Histogram
        plt.subplot(2, 2, 1)
        plt.hist(times, bins=50, alpha=0.7, edgecolor='black')
        plt.xlabel('Execution Time (ms)')
        plt.ylabel('Frequency')
        plt.title('Timing Distribution')
        
        # Box plot
        plt.subplot(2, 2, 2)
        plt.boxplot(times)
        plt.ylabel('Execution Time (ms)')
        plt.title('Timing Spread')
        
        # Time series
        plt.subplot(2, 2, 3)
        plt.plot(times, alpha=0.7)
        plt.xlabel('Measurement Number')
        plt.ylabel('Execution Time (ms)')
        plt.title('Timing Over Time')
        
        # Correlation with input length
        plt.subplot(2, 2, 4)
        input_lengths = [len(m.input_data) for m in analysis_result.measurements]
        plt.scatter(input_lengths, times, alpha=0.5)
        plt.xlabel('Input Length')
        plt.ylabel('Execution Time (ms)')
        plt.title(f'Correlation: {analysis_result.correlation_results["length_correlation"]:.3f}')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Plot saved to {save_path}")
        
        plt.show()
    
    def differential_power_analysis(self, encryption_function: Callable, 
                                  num_traces: int = 1000) -> AnalysisResult:
        """
        Simulate Differential Power Analysis (DPA) attack
        """
        logger.info(f"Starting DPA simulation with {num_traces} traces")
        
        # Generate random plaintexts and keys
        plaintexts = [secrets.token_bytes(16) for _ in range(num_traces)]
        fixed_key = secrets.token_bytes(16)
        
        power_traces = []
        measurements = []
        
        for i, plaintext in enumerate(plaintexts):
            # Simulate power consumption during encryption
            power_consumption = self.simulate_power_consumption(plaintext, "AES")
            
            # Measure execution time as well
            execution_time, ciphertext = self.measure_execution_time(
                encryption_function, plaintext, fixed_key
            )
            
            measurement = TimingMeasurement(
                input_data=plaintext,
                execution_time=execution_time,
                attempt=i,
                additional_info={
                    'power_consumption': power_consumption,
                    'ciphertext': ciphertext
                }
            )
            measurements.append(measurement)
            power_traces.append(power_consumption)
        
        # DPA analysis - correlate power with data bits
        dpa_results = self.analyze_dpa_correlation(plaintexts, power_traces)
        
        stats = {
            'mean_power': statistics.mean(power_traces),
            'power_variance': statistics.variance(power_traces) if len(power_traces) > 1 else 0,
            'trace_count': num_traces
        }
        
        vulnerability = {
            'dpa_successful': dpa_results['max_correlation'] > 0.1,
            'max_correlation': dpa_results['max_correlation'],
            'vulnerable_bits': dpa_results['vulnerable_bits']
        }
        
        return AnalysisResult(
            attack_type=AttackType.POWER_ANALYSIS,
            measurements=measurements,
            statistics=stats,
            correlation_results=dpa_results,
            vulnerability_assessment=vulnerability
        )
    
    def analyze_dpa_correlation(self, plaintexts: List[bytes], power_traces: List[float]) -> Dict:
        """Analyze correlation for DPA attack"""
        if not plaintexts or not power_traces:
            return {}
        
        # Focus on first byte for simplicity
        first_bytes = [pt[0] for pt in plaintexts]
        
        # Calculate correlation for each bit position
        bit_correlations = []
        for bit_pos in range(8):
            bit_values = [(fb >> bit_pos) & 1 for fb in first_bytes]
            
            if len(set(bit_values)) > 1:  # Ensure we have both 0 and 1
                correlation = np.corrcoef(bit_values, power_traces)[0, 1]
                bit_correlations.append((bit_pos, abs(correlation)))
            else:
                bit_correlations.append((bit_pos, 0))
        
        max_correlation = max([corr for _, corr in bit_correlations]) if bit_correlations else 0
        vulnerable_bits = [pos for pos, corr in bit_correlations if corr > 0.1]
        
        return {
            'bit_correlations': dict(bit_correlations),
            'max_correlation': max_correlation,
            'vulnerable_bits': vulnerable_bits
        }
    
    def cache_timing_attack_simulation(self) -> AnalysisResult:
        """
        Simulate cache timing attack (Flush+Reload / Prime+Probe)
        """
        logger.info("Simulating cache timing attack")
        
        # Simulate secret-dependent memory access
        secret_table = [secrets.randbits(256) for _ in range(256)]
        
        def secret_dependent_access(secret_byte: int):
            # Secret-dependent memory access pattern
            start_time = time.perf_counter_ns()
            _ = secret_table[secret_byte % len(secret_table)]  # Access based on secret
            end_time = time.perf_counter_ns()
            return (end_time - start_time) / 1e6  # Convert to milliseconds
        
        measurements = []
        cache_times = []
        
        # Test all possible byte values
        for test_byte in range(256):
            times = []
            for _ in range(10):  # Multiple measurements per byte
                access_time = secret_dependent_access(test_byte)
                times.append(access_time)
            
            avg_time = statistics.mean(times)
            cache_times.append(avg_time)
            
            measurement = TimingMeasurement(
                input_data=bytes([test_byte]),
                execution_time=avg_time,
                attempt=test_byte,
                additional_info={'cache_access': True}
            )
            measurements.append(measurement)
        
        # Analyze cache timing patterns
        fast_access_threshold = statistics.median(cache_times) * 0.8
        cached_indices = [i for i, t in enumerate(cache_times) if t < fast_access_threshold]
        
        stats = {
            'mean_access_time': statistics.mean(cache_times),
            'cached_entries': len(cached_indices),
            'timing_variation': max(cache_times) - min(cache_times)
        }
        
        vulnerability = {
            'cache_leak_detected': len(cached_indices) > 0,
            'cached_indices_count': len(cached_indices),
            'access_pattern_leak': True  # Always true in this simulation
        }
        
        return AnalysisResult(
            attack_type=AttackType.CACHE_ATTACK,
            measurements=measurements,
            statistics=stats,
            correlation_results={'cached_indices': cached_indices},
            vulnerability_assessment=vulnerability
        )
    
    def generate_report(self, analysis_results: List[AnalysisResult]) -> Dict:
        """Generate comprehensive side-channel analysis report"""
        report = {
            'timestamp': time.time(),
            'analyses': [],
            'overall_risk_assessment': {},
            'recommendations': []
        }
        
        high_risk_count = 0
        for result in analysis_results:
            analysis_data = {
                'attack_type': result.attack_type.value,
                'vulnerability_detected': result.vulnerability_assessment.get('has_timing_leak', False) or 
                                         result.vulnerability_assessment.get('dpa_successful', False) or
                                         result.vulnerability_assessment.get('cache_leak_detected', False),
                'statistics': result.statistics,
                'vulnerability_details': result.vulnerability_assessment
            }
            report['analyses'].append(analysis_data)
            
            if analysis_data['vulnerability_detected']:
                high_risk_count += 1
        
        # Overall risk assessment
        risk_level = "HIGH" if high_risk_count > 0 else "MEDIUM" if len(analysis_results) > 0 else "LOW"
        report['overall_risk_assessment'] = {
            'risk_level': risk_level,
            'vulnerable_attack_types': high_risk_count,
            'total_analyses': len(analysis_results)
        }
        
        # Generate recommendations
        if high_risk_count > 0:
            report['recommendations'].extend([
                "Implement constant-time algorithms for sensitive operations",
                "Use hardware countermeasures where available",
                "Apply blinding techniques for cryptographic operations",
                "Utilize cache-hardened implementations",
                "Conduct regular side-channel vulnerability assessments"
            ])
        
        return report

class CountermeasureTester:
    """Test effectiveness of side-channel countermeasures"""
    
    def __init__(self):
        self.analyzer = SideChannelAnalyzer()
    
    def test_constant_time_implementation(self):
        """Test if constant-time implementation is truly constant-time"""
        secret = "MySecretPassword123"
        test_inputs = [f"{secret[:i]}x" for i in range(len(secret) + 1)]
        
        insecure_times = []
        secure_times = []
        
        for test_input in test_inputs:
            # Test insecure comparison
            time_ins, _ = self.analyzer.measure_execution_time(
                self.analyzer.insecure_string_comparison, test_input, secret
            )
            insecure_times.append(time_ins)
            
            # Test secure comparison
            time_sec, _ = self.analyzer.measure_execution_time(
                self.analyzer.secure_string_comparison, test_input, secret
            )
            secure_times.append(time_sec)
        
        # Calculate variation
        insecure_variation = max(insecure_times) - min(insecure_times)
        secure_variation = max(secure_times) - min(secure_times)
        
        return {
            'insecure_variation': insecure_variation,
            'secure_variation': secure_variation,
            'improvement_factor': insecure_variation / secure_variation if secure_variation > 0 else float('inf'),
            'constant_time_effective': secure_variation < insecure_variation * 0.1
        }
    
    def test_blinding_technique(self):
        """Test effectiveness of blinding in cryptographic operations"""
        # Simulate blinded vs unblinded RSA operations
        # (Simplified simulation for educational purposes)
        
        def unblinded_operation(data: int, exponent: int, modulus: int) -> int:
            return pow(data, exponent, modulus)
        
        def blinded_operation(data: int, exponent: int, modulus: int) -> int:
            # Simple blinding: multiply by random value before operation
            blind_factor = secrets.randbelow(modulus - 1) + 1
            blinded_data = (data * blind_factor) % modulus
            result = pow(blinded_data, exponent, modulus)
            # Remove blinding
            unblind_factor = pow(blind_factor, -exponent, modulus)
            return (result * unblind_factor) % modulus
        
        # Test both implementations
        test_values = [secrets.randbelow(1000) + 1 for _ in range(100)]
        modulus = 1000000007
        exponent = 65537
        
        unblinded_times = []
        blinded_times = []
        
        for value in test_values:
            time_unblinded, _ = self.analyzer.measure_execution_time(
                unblinded_operation, value, exponent, modulus
            )
            unblinded_times.append(time_unblinded)
            
            time_blinded, _ = self.analyzer.measure_execution_time(
                blinded_operation, value, exponent, modulus
            )
            blinded_times.append(time_blinded)
        
        # Analyze timing variations
        unblinded_var = statistics.stdev(unblinded_times) if len(unblinded_times) > 1 else 0
        blinded_var = statistics.stdev(blinded_times) if len(blinded_times) > 1 else 0
        
        return {
            'unblinded_variation': unblinded_var,
            'blinded_variation': blinded_var,
            'blinding_effective': blinded_var < unblinded_var * 0.5,
            'performance_overhead': (statistics.mean(blinded_times) / statistics.mean(unblinded_times)) - 1
        }

def main():
    """Main demonstration function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Side-Channel Attack Experiments')
    parser.add_argument('--attack', choices=['timing', 'power', 'cache', 'all'], 
                       default='all', help='Type of attack to demonstrate')
    parser.add_argument('--samples', type=int, default=1000, 
                       help='Number of samples to collect')
    parser.add_argument('--plot', action='store_true', help='Generate plots')
    
    args = parser.parse_args()
    
    print("Side-Channel Attack Experiments - Educational Tool")
    print("FOR RESEARCH AND EDUCATIONAL PURPOSES ONLY")
    print("=" * 60)
    
    analyzer = SideChannelAnalyzer()
    tester = CountermeasureTester()
    results = []
    
    if args.attack in ['timing', 'all']:
        print("\n1. TIMING ATTACK DEMONSTRATION")
        print("-" * 40)
        
        # Simple timing attack demonstration
        secret = "Secret123"
        print(f"Target secret: {secret}")
        
        # Demonstrate vulnerable string comparison
        def vulnerable_comparison(input_str):
            return analyzer.insecure_string_comparison(input_str, secret)
        
        # Collect timing measurements
        def input_generator():
            length = secrets.randbelow(15) + 1
            return ''.join(chr(secrets.randbelow(95) + 32) for _ in range(length))
        
        timing_measurements = analyzer.collect_timing_measurements(
            vulnerable_comparison, input_generator, args.samples
        )
        timing_analysis = analyzer.analyze_timing_data(timing_measurements)
        results.append(timing_analysis)
        
        print(f"Timing analysis completed:")
        print(f"  - Mean time: {timing_analysis.statistics['mean']:.6f} ms")
        print(f"  - Standard deviation: {timing_analysis.statistics['stdev']:.6f} ms")
        print(f"  - Timing leak detected: {timing_analysis.vulnerability_assessment['has_timing_leak']}")
        
        if args.plot:
            analyzer.plot_timing_distribution(timing_analysis, "timing_analysis.png")
    
    if args.attack in ['power', 'all']:
        print("\n2. POWER ANALYSIS DEMONSTRATION")
        print("-" * 40)
        
        power_analysis = analyzer.differential_power_analysis(
            analyzer.simple_aes_operation, 
            min(args.samples, 500)  # Limit for simulation
        )
        results.append(power_analysis)
        
        print(f"Power analysis completed:")
        print(f"  - Traces collected: {power_analysis.statistics['trace_count']}")
        print(f"  - Max correlation: {power_analysis.correlation_results['max_correlation']:.3f}")
        print(f"  - DPA successful: {power_analysis.vulnerability_assessment['dpa_successful']}")
    
    if args.attack in ['cache', 'all']:
        print("\n3. CACHE TIMING ATTACK DEMONSTRATION")
        print("-" * 40)
        
        cache_analysis = analyzer.cache_timing_attack_simulation()
        results.append(cache_analysis)
        
        print(f"Cache timing analysis completed:")
        print(f"  - Cached entries detected: {cache_analysis.statistics['cached_entries']}")
        print(f"  - Cache leak detected: {cache_analysis.vulnerability_assessment['cache_leak_detected']}")
    
    # Test countermeasures
    print("\n4. COUNTERMEASURE EFFECTIVENESS")
    print("-" * 40)
    
    constant_time_test = tester.test_constant_time_implementation()
    print(f"Constant-time implementation test:")
    print(f"  - Insecure variation: {constant_time_test['insecure_variation']:.6f} ms")
    print(f"  - Secure variation: {constant_time_test['secure_variation']:.6f} ms")
    print(f"  - Effective: {constant_time_test['constant_time_effective']}")
    
    blinding_test = tester.test_blinding_technique()
    print(f"Blinding technique test:")
    print(f"  - Blinding effective: {blinding_test['blinding_effective']}")
    print(f"  - Performance overhead: {blinding_test['performance_overhead']:.1%}")
    
    # Generate final report
    report = analyzer.generate_report(results)
    print(f"\n5. OVERALL RISK ASSESSMENT")
    print("-" * 40)
    print(f"Risk Level: {report['overall_risk_assessment']['risk_level']}")
    print(f"Vulnerable Attack Types: {report['overall_risk_assessment']['vulnerable_attack_types']}")
    
    if report['recommendations']:
        print("\nRECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"  • {rec}")

if __name__ == "__main__":
    main()
