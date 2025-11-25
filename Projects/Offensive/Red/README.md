# Red/Blue Exercise Scenarios Generator

### What the Tool Is For:
This tool generates realistic cybersecurity exercise scenarios for Red Team (attackers) and Blue Team (defenders) training. It creates complete engagement scenarios with objectives, attack vectors, defensive measures, and scoring criteria.

### About:
Red/Blue team exercises are crucial for improving organizational security posture. This generator helps create realistic training scenarios that simulate real-world attacks and defenses, helping teams practice incident response, threat hunting, and security operations.

## How to Run the Code

### Python Version:
```bash
# Install dependencies
pip3 install pyyaml

# Generate APT simulation scenario
python3 scenario_generator.py --scenario-type apt_simulation --infrastructure corporate_network --difficulty High --format json

# Generate ransomware scenario
python3 scenario_generator.py --scenario-type ransomware_attack --infrastructure industrial_control --difficulty Medium --format yaml

# Generate with inject
python3 scenario_generator.py --scenario-type insider_threat --infrastructure cloud_environment --inject

# Text output
python3 scenario_generator.py --scenario-type supply_chain --format text
```

### C Version:
```bash
# Compile
gcc -o scenario_generator scenario_generator.c

# Generate scenarios
./scenario_generator --scenario-type apt_simulation --infrastructure corporate_network --difficulty High --format json

./scenario_generator --scenario-type ransomware_attack --format text
```

---

##  Algorithm Explanation

### How the Scenario Generator Works:

**Scenario Composition:**
1. **Template Selection** - Chooses base scenario type (APT, ransomware, insider threat, etc.)
2. **Infrastructure Mapping** - Maps scenario to appropriate infrastructure
3. **Technique Selection** - Selects ATT&CK techniques based on difficulty
4. **Objective Generation** - Creates realistic objectives for both teams
5. **Action Planning** - Generates recommended defensive actions

**Red Team Components:**
- **Initial Access** - Phishing, exploitation, social engineering
- **Persistence** - Backdoors, scheduled tasks, service installation
- **Lateral Movement** - Credential dumping, pass-the-hash, WMI
- **Exfiltration** - Data staging, covert channels, encryption

**Blue Team Components:**
- **Detection** - SIEM rules, EDR alerts, network monitoring
- **Response** - Containment, eradication, recovery procedures
- **Forensics** - Evidence collection, timeline analysis, root cause
- **Hardening** - Configuration changes, policy updates

**Scoring System:**
- **Objective Completion** - Points for completed tasks
- **Time Efficiency** - Bonus for quick completion
- **Stealth/Detection** - Points based on OODA loop effectiveness
- **Documentation** - Quality of after-action reports
