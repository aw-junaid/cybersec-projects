# Forensic Timeline Builder

### What the Tool Is For:
This tool automatically collects and correlates forensic artifacts from filesystem metadata, logs, registry entries, and other sources to build comprehensive timelines for digital investigations.

### About:
Forensic timeline analysis is crucial for understanding the sequence of events during an incident. This tool automates the collection and correlation of timestamps from diverse sources, helping investigators reconstruct what happened and when.

---

## How to Run the Code

### Python Version:
```bash
# Install dependencies
pip3 install psutil

# Build timeline from multiple sources
python3 timeline_builder.py build --case "Investigation_001" \
    --filesystem /home/user/Documents --recursive \
    --bash-history /home/user/.bash_history \
    --apache-logs /var/log/apache2/access.log

# Query timeline
python3 timeline_builder.py query --case "Investigation_001" \
    --start "2024-01-15 10:00:00" --end "2024-01-15 11:00:00" \
    --event-types file_modified file_accessed

# Generate reports
python3 timeline_builder.py report --case "Investigation_001" --format html --output timeline.html
python3 timeline_builder.py report --case "Investigation_001" --format csv --output timeline.csv

# Analyze timeline
python3 timeline_builder.py analyze --case "Investigation_001" --correlate --patterns
```

### C Version:
```bash
# Compile with SQLite
gcc -o timeline_builder timeline_builder.c -lsqlite3

# Build timeline
./timeline_builder build Investigation_001 /home/user/Documents

# Generate report
./timeline_builder report Investigation_001 timeline_report.txt

# Correlate events
./timeline_builder correlate Investigation_001 300  # 5-minute window
```

---

## Algorithm Explanation

### How the Forensic Timeline Builder Works:

**Artifact Collection:**
1. **Filesystem Metadata** - MACB timestamps (Modified, Accessed, Changed, Birth)
2. **Log Files** - System, application, and security logs
3. **Registry Data** - Windows registry hives and keys
4. **Prefetch Files** - Windows program execution records
5. **Bash History** - Command execution history
6. **Event Logs** - Windows Event Logs (EVTX)

**Event Correlation:**
1. **Timestamp Normalization** - Convert all timestamps to common format
2. **Entity Resolution** - Map users, hosts, and artifacts
3. **Temporal Analysis** - Identify events occurring in close succession
4. **Pattern Detection** - Find sequences indicating malicious activity

**Timeline Construction:**
1. **Event Sorting** - Chronological ordering of all events
2. **Source Integration** - Merge events from multiple sources
3. **Confidence Scoring** - Assign reliability scores to events
4. **Tagging** - Categorize events for easier analysis

**Analysis Features:**
- **Temporal Correlation** - Group events within time windows
- **Behavioral Patterns** - Detect common attack sequences
- **Statistical Analysis** - Event frequency and distribution
- **Anomaly Detection** - Identify unusual activity patterns
