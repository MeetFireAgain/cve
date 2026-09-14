# Bug Report

## Affected Software
- **Product: LightFTP** (https://github.com/hfiref0x/LightFTP)
- **Version(s): master snapshot 2026-06-15 (`FTP_VERSION "2.4"`, post-v2.3.1); stor logic unchanged since v1.x — likely all versions**
- **Vendor: hfiref0x**

## Vulnerability Type
Silent Data Loss / Integrity Violation on write() failure (CWE-252: Unchecked Return Value; result: CWE-460 improper cleanup)

## Description
A silent data-loss vulnerability exists in the `stor_thread` upload path of LightFTP (`src/ftpserv.c`).

While handling the FTP `STOR` command, the receive loop breaks as soon as `write(file_fd, ...)` fails or writes fewer bytes than received (disk full, quota exceeded, file size limit, I/O error):

```c
// src/ftpserv.c, stor_thread
1356:  while ( context->worker_thread_abort == 0 ) {
1357:      sz = recv_auto(client_socket, TLS_datasession, buffer, buffer_size);
1358:      if (sz > 0)
1359:      {
1360:          sz_total += sz;
1361:          wsz = write(file_fd, buffer, (size_t)sz);
1362:          if (wsz != sz)
1363:              break;                       // <-- write() failure exits loop
1364:      }
...
1399:  if (context->worker_thread_abort == 0)   // <-- abort flag is NOT set on write error
1400:      sendstring(context, success226);     // <-- client is told "226 Transfer complete"
```

Because the loop-exit via write error never sets `worker_thread_abort`, the server sends **`226 Transfer complete`** to the client even though the file on disk is truncated. The client (and any automation relying on FTP status codes) believes the upload succeeded.

`write()` failure was reproduced in **two independent ways**:

1. **Real disk full (no tooling)**: the FTP root is placed on an 8 KB tmpfs filesystem; a 100 KB upload fills it for real. Server replies `226 Transfer complete`, on-disk file is 0 bytes. See `tmpfs_run.sh`, `poc_tmpfs.py`, `write_error_step3_real_disk_full.png`.
2. **Deterministic fault injection**: an `LD_PRELOAD` library returns `ENOSPC` after 512 bytes (`fault_injector.c`) — equivalent to a real "quota exceeded / disk full at a chosen offset" condition, with a no-injector control run proving the difference (`detailed_run.sh`, `write_error_step1/2_*.png`).

## Proof of Concept (PoC)

PoC files in this directory:
- `poc_tmpfs.py` + `tmpfs_run.sh` + `fftp_tmpfs.conf` — **primary PoC: real full disk via 8 KB tmpfs, no LD_PRELOAD**
- `poc_write_error.py` — FTP client that uploads a 2048-byte file and prints the server response + on-disk size
- `fault_injector.c` — LD_PRELOAD library that fails `write()` with `ENOSPC` after 512 bytes for the target file (deterministic variant)
- `detailed_run.sh` — one-command full reproduction (build + control test + vulnerable test + verification)
- `write_error_step1_env_build_control.png`, `write_error_step2_inject_vuln_verify.png`, `write_error_step3_real_disk_full.png` — reproduction screenshots
- `detailed_evidence.txt`, `tmpfs_evidence.txt` — full terminal logs

## Steps to Reproduce

```bash
# any x64/arm64 Linux or docker container (tested: ubuntu:24.04)
# 1. build
cd LightFTP/src && gcc -O1 -g -o /tmp/fftp *.c -pthread -lgnutls
# 2. prepare fftp.conf (see fftp.conf in this dir) and ftpshare/
# 3. start server with the fault injector
gcc -shared -fPIC -o fault_injector.so fault_injector.c -ldl
LD_PRELOAD=$PWD/fault_injector.so /tmp/fftp fftp.conf &
# 4. upload
python3 poc_write_error.py
```

Observed output:

```
[*] Server final response: 226 Transfer complete. Closing data connection.
[*] Sent 2048 bytes, on disk: 512 bytes
[!] VULNERABILITY CONFIRMED: 226 success returned but file truncated
```

Control test (same upload **without** the injector) stores the full 2048 bytes and also returns 226 — confirming the truncation is caused by the unhandled `write()` failure, while the status code stays wrong only in the failure case.

Real-disk-full test (no LD_PRELOAD at all — primary evidence):

```bash
mount -t tmpfs -o size=8k tmpfs /tmp/tinyfs && mkdir -p /tmp/tinyfs/ftpshare
/work/fftp_plain /tmp/tinyfs/fftp.conf &        # FTP root on the 8 KB tmpfs
python3 poc_tmpfs.py                            # uploads 100 KB
```

Observed output:

```
[*] Server final response: 226 Transfer complete. Closing data connection.
[*] Sent 100000 bytes, on disk: 0 bytes
[!] VULNERABILITY CONFIRMED WITH REAL FULL DISK (tmpfs, no LD_PRELOAD)
--- [4] disk state after upload ---
tmpfs           8.0K  8.0K     0 100% /tmp/tinyfs
```

## Impact
* **Integrity**: uploads are silently truncated; backups/mirrors built over FTP propagate corrupted files while believing transfers succeeded
* **Availability/Reliability**: any deployment where the storage fills (log partitions, quota-limited containers, embedded/IoT devices with small flash) silently loses data
* **Authentication**: any account with `upload`/`admin` rights is affected; the error condition itself needs no attacker

## Suggested Fix
Track the write-failure exit distinctly from an abort, e.g. set a `write_error` flag when `wsz != sz` and reply `451 Requested action aborted: local error in processing` (or `426`) instead of `226`.
