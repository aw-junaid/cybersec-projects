#!/usr/bin/env python3
"""
sim_client.py - Reverse Shell Simulator (Client)
Safe: does NOT forward a real shell. Connects and interacts with simulator.
Usage: python3 sim_client.py --host HOST --port PORT --token TOKEN
"""
import argparse, socket, json, struct, threading, sys

def send_msg(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn):
    hdr = conn.recv(4)
    if not hdr:
        return None
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))

def interactive_loop(conn):
    # read initial messages
    while True:
        msg = recv_msg(conn)
        if not msg: 
            print("[*] Connection closed by server")
            return
        if msg.get("type") == "notice":
            print("[NOTICE]", msg.get("msg"))
            break
    try:
        while True:
            cmd = input("sim-shell> ").strip()
            if cmd in ("exit","quit"):
                print("[*] Exiting")
                conn.close()
                return
            if cmd == "":
                continue
            send_msg(conn, {"type":"command","command":cmd})
            resp = recv_msg(conn)
            if not resp:
                print("[*] Server closed connection")
                return
            if resp.get("type") == "result":
                print(resp.get("stdout",""))
                if resp.get("stderr"):
                    print("[ERR]", resp.get("stderr"), file=sys.stderr)
                print(f"[exit_code={resp.get('exit_code')}]")
            else:
                print("[?]", resp)
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Interrupted, closing")
        conn.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--token", required=True)
    args = p.parse_args()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((args.host, args.port))
    send_msg(s, {"type":"auth","token":args.token})
    auth = recv_msg(s)
    if not auth or not auth.get("ok"):
        print("Auth failed:", auth)
        s.close()
        return
    interactive_loop(s)

if __name__ == "__main__":
    main()
