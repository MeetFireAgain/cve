import socket, struct, time, threading
HOST, PORT = "192.168.77.1", 2000
lock = threading.Lock(); stats = {"conn":0, "auth":0, "frames":0}
def handle(conn, cid):
    conn.settimeout(2.5)
    try:
        conn.sendall(bytes([1,0,0,0]))
        d1 = conn.recv(8)
        d2 = conn.recv(32)
        conn.sendall(bytes([1,0,0,0]))      # AUTH_OK
        with lock: stats["auth"] += 1
        seq = cid; t0 = time.time(); n = 0
        conn.settimeout(3)
        while time.time()-t0 < 8:
            conn.sendall(struct.pack("<I", seq & 0xffffffff) + b"A"*1400)
            seq += 7919; n += 1
        with lock: stats["frames"] += n
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT)); s.listen(64); s.settimeout(300)
print("[listening threaded]", flush=True)
cid = 0
t0 = time.time()
while time.time()-t0 < 3600:
    try:
        conn, addr = s.accept()
        with lock: stats["conn"] += 1
        threading.Thread(target=handle, args=(conn,cid), daemon=True).start()
        cid += 1
        if cid % 20 == 0:
            with lock: print(f"[{int(time.time()-t0)}s] conn={stats['conn']} auth={stats['auth']} frames={stats['frames']}", flush=True)
    except socket.timeout:
        continue
