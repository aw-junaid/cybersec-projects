# Digital Forensic Analysis Lab

### What the Tool Is For:
This toolkit provides capabilities to capture, analyze, and interpret digital forensic artifacts from various sources including memory, disk images, and system logs. It's designed for incident response and forensic investigations.

### About:
Digital forensics involves the preservation, collection, validation, identification, analysis, interpretation, and documentation of digital evidence. This lab provides foundational tools for memory analysis, disk forensics, timeline creation, and artifact extraction.


## How to Run the Code

### Python Version:
```bash
# Install dependencies
pip3 install pyopenssl

# Analyze memory dump
python3 forensic_lab.py memory -i memory.dmp -o memory_analysis.json

# Analyze disk image  
python3 forensic_lab.py disk -i disk.img -o disk_analysis.json

# Extract artifacts
python3 forensic_lab.py artifacts -i /evidence/ -o artifacts.json

# Complete forensic analysis
python3 forensic_lab.py full -m memory.dmp -d disk.img -a /evidence/ -o full_report.json
```

### C Version:
```bash
# Compile with OpenSSL
gcc -o forensic_lab forensic_lab.c -lssl -lcrypto

# Analyze memory
./forensic_lab memory memory.dmp memory_report.txt

# Analyze disk
./forensic_lab disk disk.img disk_report.txt

# Generate full report
./forensic_lab report memory.dmp disk.img forensic_report.txt
```

---

##  Algorithm Explanation

### How the Forensic Analysis Lab Works:

**Memory Analysis:**
1. **Process Extraction** - Identifies running processes and their relationships
2. **Network Analysis** - Maps network connections to processes
3. **String Extraction** - Recovers ASCII strings from memory
4. **Malware Detection** - Identifies suspicious patterns and IOCs

**Disk Analysis:**
1. **File System Analysis** - Examines file system structures and metadata
2. **Timeline Creation** - Builds chronological sequence of events
3. **Deleted File Recovery** - Attempts to recover erased files
4. **Registry Analysis** - Extracts Windows registry artifacts

**Artifact Extraction:**
1. **System Artifacts** - Hostname, OS version, user accounts
2. **User Activity** - Recent documents, run commands, clipboard
3. **Network Artifacts** - ARP cache, DNS cache, connection history
4. **Application Artifacts** - Browser history, email, instant messaging

**Forensic Techniques:**
- **Hashing** - File integrity verification
- **Timeline Analysis** - Event correlation
- **Pattern Matching** - IOC detection
- **Metadata Analysis** - File system artifacts
