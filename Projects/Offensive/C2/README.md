# C2 Mini Framework

### What the Tool Is For:
This tool demonstrates C2 functionality for educational purposes, showing how attackers maintain persistence and control compromised systems. It helps security professionals understand C2 techniques for defensive purposes.

### About:
Command & Control frameworks are used by attackers to maintain communication with compromised systems. Understanding their architecture is crucial for blue teams to detect and prevent such attacks. This mini-framework implements basic C2 features in a controlled lab environment.


## How to Run the Code

### Python Version:
```bash
# Install dependencies
pip3 install cryptography

# Start C2 Server
python3 c2_framework.py --mode server --host 0.0.0.0 --port 4444

# Start C2 Client (in another terminal)
python3 c2_framework.py --mode client --server-host 127.0.0.1 --port 4444

# Multiple clients can connect to the same server
```

### C Version:
```bash
# Compile Server
gcc -o c2_server c2_framework.c -lcrypto -lpthread

# Compile Client  
gcc -o c2_client c2_framework.c -lcrypto -lpthread -DCLIENT_MODE

# Start C2 Server
./c2_server --server --port 4444

# Start C2 Client
./c2_client --client 127.0.0.1 --port 4444
```

---

## Algorithm Explanation

### How the C2 Framework Works:

**Server Components:**
1. **Listener** - Binds to port and accepts client connections
2. **Client Handler** - Manages individual client sessions
3. **Command Queue** - Stores pending commands for clients
4. **Encryption** - Secures communications

**Client Components:**
1. **Beaconing** - Periodic check-ins with C2 server
2. **Command Execution** - Runs received commands
3. **Result Reporting** - Sends command outputs back
4. **Persistence** - Maintains connection despite failures

**Communication Flow:**
1. **Check-in** → Client establishes encrypted connection
2. **Authentication** → Client proves identity
3. **Command Delivery** → Server sends encrypted commands
4. **Execution** → Client runs commands locally
5. **Exfiltration** → Results sent back to server
6. **Beacon** → Regular heartbeat to maintain presence

**Key Features:**
- Encrypted communications
- Client identification and tracking
- Command execution pipeline
- Error handling and reconnection
- Basic persistence mechanisms
