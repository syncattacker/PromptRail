| Test # | Test Name                 | Status   | Reason / Observation                                                                                                      |
| ------ | ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| **1**  | curl write path           | **PASS** | Captured the `dir="write"` event with the expected `comm=curl` and payload.                                               |
| **2**  | curl read path            | **PASS** | Successfully returned the `dir="read"` event with the response bytes.                                                     |
| **3**  | python3 gate              | **FAIL** | No capture events were triggered for the Python script; only periodic stat lines appeared.                                |
| **4**  | attribution correctness   | **PASS** | The PID reported by the daemon correctly matched the background `curl` process PID.                                       |
| **5**  | canary soak test          | **FAIL** | The expected `X-PromptRail-Canary` header was missing from the captured plaintext.                                        |
| **6**  | multithreaded correctness | **PASS** | Handled concurrent TLS calls cleanly without splicing or corrupting the payloads across threads.                          |
| **7**  | coverage boundary         | **FAIL** | The daemon incorrectly classified `gnutls-cli` as an OpenSSL backend instead of logging the required coverage warning.    |
| **8**  | portability gate          | **FAIL** | The compiled eBPF object was rejected during load because it uses a legacy `maps` format not supported by `libbpf` v1.0+. |
