#!/usr/bin/env python3
"""
Container Security Scanner - FastAPI Microservice
Provides image scanning, SBOM generation, and signature verification
"""

import json
import subprocess
import tempfile
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
import docker
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import httpx
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Container Security Scanner",
    description="REST API for container image security scanning and analysis",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    image: str = Field(..., description="Container image reference to scan")
    timeout: int = Field(300, description="Scan timeout in seconds")
    fail_threshold: int = Field(50, description="Risk score threshold for failure")
    verify_signature: bool = Field(True, description="Whether to verify image signature")

class ScanResult(BaseModel):
    image: str
    risk_score: int
    vulnerabilities: List[Dict[str, Any]]
    sbom: Optional[Dict[str, Any]]
    signature_verified: bool
    security_issues: List[str]
    passed: bool
    scan_duration: float

class VulnerabilityDB:
    """Simple in-memory vulnerability database for demo purposes"""
    def __init__(self):
        self.vulns = {
            "CVE-2021-44228": {"severity": "CRITICAL", "package": "log4j", "score": 10},
            "CVE-2021-45046": {"severity": "HIGH", "package": "log4j", "score": 8},
            "CVE-2019-1010218": {"severity": "MEDIUM", "package": "glibc", "score": 5},
        }
    
    def check_vulnerability(self, package: str, version: str) -> List[Dict]:
        """Check package against vulnerability database"""
        found = []
        for cve_id, vuln in self.vulns.items():
            if vuln["package"] in package.lower():
                found.append({
                    "cve_id": cve_id,
                    "severity": vuln["severity"],
                    "package": package,
                    "version": version,
                    "score": vuln["score"]
                })
        return found

vuln_db = VulnerabilityDB()

def run_command(cmd: List[str], timeout: int = 300) -> tuple[str, str, int]:
    """Execute shell command with timeout"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        raise HTTPException(408, f"Command timed out: {' '.join(cmd)}")
    except Exception as e:
        raise HTTPException(500, f"Command execution failed: {str(e)}")

async def scan_image_with_trivy(image: str, timeout: int) -> Dict[str, Any]:
    """Scan image using Trivy"""
    try:
        # Use Trivy JSON output
        cmd = ["trivy", "image", "--format", "json", "--quiet", image]
        stdout, stderr, returncode = await asyncio.to_thread(
            run_command, cmd, timeout
        )
        
        if returncode != 0 and "timeout" not in stderr.lower():
            logger.warning(f"Trivy scan completed with warnings: {stderr}")
        
        try:
            return json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Trivy output: {stdout}")
            return {}
            
    except Exception as e:
        logger.error(f"Trivy scan failed: {str(e)}")
        return {}

async def generate_sbom(image: str, timeout: int) -> Dict[str, Any]:
    """Generate SBOM using Trivy"""
    try:
        cmd = ["trivy", "image", "--format", "cyclonedx", "--quiet", image]
        stdout, stderr, returncode = await asyncio.to_thread(
            run_command, cmd, timeout
        )
        
        if stdout:
            return {"format": "cyclonedx", "content": json.loads(stdout)}
        return {}
    except Exception as e:
        logger.error(f"SBOM generation failed: {str(e)}")
        return {}

async def verify_signature(image: str) -> bool:
    """Verify image signature using cosign"""
    try:
        cmd = ["cosign", "verify", image]
        stdout, stderr, returncode = await asyncio.to_thread(run_command, cmd, 60)
        
        # cosign returns 0 on successful verification
        return returncode == 0
    except Exception as e:
        logger.warning(f"Signature verification failed: {str(e)}")
        return False

def calculate_risk_score(vulnerabilities: List[Dict], signature_verified: bool, security_issues: List[str]) -> int:
    """Calculate overall risk score"""
    score = 0
    
    # Score vulnerabilities
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW")
        if severity == "CRITICAL":
            score += 10
        elif severity == "HIGH":
            score += 8
        elif severity == "MEDIUM":
            score += 5
        elif severity == "LOW":
            score += 1
    
    # Penalty for missing signature
    if not signature_verified:
        score += 20
    
    # Penalty for security issues
    score += len(security_issues) * 5
    
    return score

def check_security_issues(image_metadata: Dict) -> List[str]:
    """Check for common security misconfigurations"""
    issues = []
    
    # Check for root user
    if image_metadata.get("user") in ["root", "0"]:
        issues.append("Container runs as root")
    
    # Check for exposed ports
    exposed_ports = image_metadata.get("exposed_ports", [])
    if any("22" in port for port in exposed_ports):
        issues.append("SSH port exposed")
    
    return issues

@app.post("/scan", response_model=ScanResult)
async def scan_image(request: ScanRequest, background_tasks: BackgroundTasks):
    """Scan container image for vulnerabilities and security issues"""
    import time
    start_time = time.time()
    
    logger.info(f"Starting scan for image: {request.image}")
    
    try:
        # Run scans concurrently
        scan_tasks = [
            scan_image_with_trivy(request.image, request.timeout),
            generate_sbom(request.image, request.timeout),
            verify_signature(request.image) if request.verify_signature else asyncio.sleep(0)
        ]
        
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Extract results
        trivy_result = results[0] if not isinstance(results[0], Exception) else {}
        sbom_result = results[1] if not isinstance(results[1], Exception) else {}
        signature_verified = results[2] if request.verify_signature and not isinstance(results[2], Exception) else True
        
        if isinstance(results[0], Exception):
            logger.error(f"Trivy scan failed: {results[0]}")
        if isinstance(results[1], Exception):
            logger.error(f"SBOM generation failed: {results[1]}")
        
        # Extract vulnerabilities
        vulnerabilities = []
        if trivy_result and "Results" in trivy_result:
            for result in trivy_result["Results"]:
                if "Vulnerabilities" in result:
                    vulnerabilities.extend(result["Vulnerabilities"])
        
        # Check security issues (simplified)
        security_issues = check_security_issues({})
        
        # Calculate risk score
        risk_score = calculate_risk_score(vulnerabilities, signature_verified, security_issues)
        
        # Determine if scan passed
        passed = risk_score < request.fail_threshold
        
        scan_duration = time.time() - start_time
        
        result = ScanResult(
            image=request.image,
            risk_score=risk_score,
            vulnerabilities=vulnerabilities[:10],  # Limit for demo
            sbom=sbom_result,
            signature_verified=signature_verified,
            security_issues=security_issues,
            passed=passed,
            scan_duration=scan_duration
        )
        
        logger.info(f"Scan completed for {request.image}: risk_score={risk_score}, passed={passed}")
        
        return result
        
    except Exception as e:
        logger.error(f"Scan failed for {request.image}: {str(e)}")
        raise HTTPException(500, f"Scan failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "container-scanner"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
