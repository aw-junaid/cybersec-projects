# DLP Demo - Lab Safety Rules

## ⚠️ CRITICAL SAFETY NOTICE

**THIS DEMO SYSTEM IS FOR LABORATORY USE ONLY. NEVER DEPLOY TO PRODUCTION OR USE WITH REAL USER DATA.**

## Safety Rules

### 1. Environment Isolation
- Only run in isolated lab environments
- Verify `DLP_LAB_MODE=1` is set before execution
- No internet connectivity to production systems
- Use synthetic/test data exclusively

### 2. Data Handling
- Never process real user data, PII, or sensitive information
- All test data must be synthetic/generated
- Redact any accidental real data immediately
- 24-hour maximum log retention in lab

### 3. Network Safety
- No connections to production networks
- Use lab-only DNS servers
- Block all outbound internet access during tests
- Verify isolation with `check_isolated.py`

### 4. Destructive Actions
- Automatic blocking/quarantine disabled by default
- Require `--enable-actions` flag for destructive operations
- Manual confirmation required for each destructive action
- All actions are simulated unless explicitly enabled

### 5. Legal Compliance
- This is a demonstration tool only
- Not intended for production use
- No warranty or support provided
- Users responsible for compliance with local laws

## Quick Safety Checklist

- [ ] Environment variable `DLP_LAB_MODE=1` set
- [ ] Running in isolated lab network
- [ ] Using synthetic test data only
- [ ] No production systems accessible
- [ ] Destructive actions disabled/confirmed

## Emergency Stop

If the system accidentally contacts production:

1. Immediately disconnect lab network
2. Stop all DLP demo processes
3. Review logs for any data exposure
4. Contact security team

## Compliance

This tool complies with:
- Lab safety best practices
- Data protection principles (synthetic data only)
- Responsible disclosure requirements
