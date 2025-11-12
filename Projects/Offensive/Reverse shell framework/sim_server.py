#!/usr/bin/env python3
"""
sim_server.py - Reverse Shell Simulator (Server)
Safe: does NOT execute shell commands. Runs on localhost by default.
Usage: python3 sim_server.py [--host HOST] [--port PORT] [--token TOKEN] [--log LOGFILE]
Example: python3 sim_server.py --host 127.0.0.1 --port 9000 --token mysecret
"""
import argparse, socket, threading, json, struct, time, datetime, logging

# -- Configuration / safe defaults --
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000
DEFAULT_TOKEN = "lab-token"
LOGFILE = "sim_server.log"
INACTIVITY_TIMEOUT = 300  # seconds

# -- Simple framed JSON protocol helpers (length-prefixed) --
def send_msg(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn, timeout=10):
    conn.settimeout(timeout)
    hdr = b""
    try:
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
    except socket.timeout:
        return None
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))

# -- Simulated command handlers (whitelisted) --
SIMULATED_CMDS = {
    "uname": lambda args: ("Linux lab-sim 5.10.0-0", "", 0),
    "whoami": lambda args: ("student", "", 0),
    "echo": lambda args: (" ".join(args), "", 0),
    "date": lambda args: (datetime.datetime.utcnow().isoformat() + "Z", "", 0),
    "help": lambda args: ("Available commands: " + ", ".join(sorted(SIMULATED_CMDS.keys())), "", 0)
}

def handle_command(cmd_line):
    parts = cmd_line.strip().split()
    if not parts:
        return ("", "empty command", 1)
    cmd = parts[0]
    args = parts[1:]
    if cmd in SIMULATED_CMDS:
        try:
            out, err, code = SIMULATED_CMDS[cmd](args)
            return (out, err, code)
        except Exception as e:
            return ("", f"handler error: {e}", 2)
    else:
        return ("", f"command '{cmd}' not recognized in simulator", 127)

# -- Per-connection worker --
def client_worker(conn, addr, token_expected, logger):
    logger.info(f"Connection from {addr}")
    # Authenticate
    auth = recv_msg(conn, timeout=10)
    if not auth or auth.get("type") != "auth" or auth.get("token") != token_expected:
        logger.warning(f"Auth failed from {addr}")
        send_msg(conn, {"type":"auth_result", "ok":False, "reason":"invalid token"})
        conn.close()
        return
    send_msg(conn, {"type":"auth_result", "ok":True})
    last_activity = time.time()
    send_msg(conn, {"type":"notice", "msg":"Authenticated. This is a SIMULATOR. No commands will be executed on the OS."})
    try:
        while True:
            msg = recv_msg(conn, timeout=INACTIVITY_TIMEOUT)
            if not msg:
                logger.info(f"Connection closed / timeout from {addr}")
                break
            last_activity = time.time()
            if msg.get("type") == "ping":
                send_msg(conn, {"type":"pong"})
                continue
            if msg.get("type") == "command":
                cmd_text = msg.get("command","")
                logger.info(f"CMD from {addr}: {cmd_text}")
                out, err, code = handle_command(cmd_text)
                resp = {"type":"result", "stdout":out, "stderr":err, "exit_code":code}
                send_msg(conn, resp)
                logger.info(f"RESP to {addr}: exit={code}")
            else:
                send_msg(conn, {"type":"error","msg":"unknown message type"})
    except Exception as e:
        logger.exception(f"Worker error for {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"Disconnected {addr}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--token", default=DEFAULT_TOKEN)
    p.add_argument("--log", default=LOGFILE)
    args = p.parse_args()

    logging.basicConfig(filename=args.log, level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    logger = logging.getLogger("sim_server")
    logger.info("Starting Reverse Shell Simulator (server)")
    logger.info(f"Listening on {args.host}:{args.port}, token='{args.token}' (keep this secret for the lab)")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args.host, args.port))
    s.listen(5)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=client_worker, args=(conn, addr, args.token, logger), daemon=True)
            t.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
