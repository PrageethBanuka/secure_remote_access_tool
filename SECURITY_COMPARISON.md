# Security Comparison: Before vs. After

This document provides a side-by-side comparison of the security properties of the Secure Remote Access Tool before and after the hardening changes. It is intended as an academic reference for understanding **why** each change was made and **what threat** it mitigates.

---

## 1. Summary of Changes

| # | Area | Before | After | Files Changed |
|---|------|--------|-------|---------------|
| 1 | Encryption Mode | AES/ECB/PKCS5Padding | AES/GCM/NoPadding | `SecurityUtils.java` |
| 2 | Key Size | AES-128 | AES-256 | `SecurityUtils.java` |
| 3 | IV Usage | None (ECB has no IV) | Random 12-byte IV per encryption | `SecurityUtils.java` |
| 4 | Message Integrity | None | GCM authentication tag (128-bit) | `SecurityUtils.java` |
| 5 | Key Exchange | AES key sent in **plaintext** over TCP | RSA-2048 OAEP hybrid exchange | All 3 files |
| 6 | RSA Padding | N/A | OAEP with SHA-256 + MGF1 | `SecurityUtils.java` |
| 7 | Session Keys | Single shared key for all clients | Per-client unique session key | `SecureServer.java`, `SecureClient.java` |
| 8 | Password Storage | Plaintext (`"secure123"`) | PBKDF2-HMAC-SHA256 hash + salt | `SecurityUtils.java`, `SecureServer.java` |
| 9 | Password Comparison | `String.equals()` | Constant-time XOR comparison | `SecurityUtils.java` |
| 10 | Brute-force Protection | None | 3-attempt limit, 30s IP lockout | `SecureServer.java`, `SecureClient.java` |
| 11 | Command Logging | Full plaintext command logged | IP + character count only | `SecureServer.java` |
| 12 | Socket Timeout | None (indefinite) | 5-minute timeout | `SecureServer.java`, `SecureClient.java` |

---

## 2. Detailed Comparisons

### 2.1 Encryption Mode: ECB vs. GCM

| Property | AES/ECB | AES/GCM |
|----------|---------|---------|
| **How it works** | Each 16-byte block encrypted independently with the same key | Counter mode encryption + Galois field MAC |
| **IV/Nonce** | None | 12-byte random nonce per message |
| **Pattern leakage** | Identical plaintext blocks → identical ciphertext blocks (the "ECB penguin" problem) | Random IV ensures different output every time |
| **Integrity** | None — ciphertext can be modified without detection | 128-bit authentication tag detects any tampering (`AEADBadTagException`) |
| **Padding** | PKCS5Padding required | No padding needed (stream-like) |
| **Parallelizable** | Encryption & decryption both parallelizable | Encryption sequential, decryption parallelizable |
| **Security proof** | Known insecure for multi-block messages | Provably secure under standard assumptions |

**Real-world example:** In ECB mode, encrypting the same command (e.g., `"ls"`) always produces the same ciphertext — an attacker can build a dictionary of command→ciphertext mappings. In GCM mode, `"ls"` encrypted twice produces completely different ciphertexts.

### 2.2 Key Exchange: Plaintext vs. RSA-OAEP Hybrid

| Property | Before (Plaintext) | After (RSA-OAEP Hybrid) |
|----------|-------------------|------------------------|
| **Mechanism** | Server generates AES key, sends Base64-encoded key directly over TCP | Server sends RSA public key; client generates AES key, encrypts with RSA-OAEP, sends to server |
| **Network sniffing** | Anyone capturing packets sees the AES key in cleartext | Attacker sees only the RSA public key (useless without private key) and the RSA-encrypted AES key (requires private key to decrypt) |
| **Key compromise** | Trivial — single packet capture | Requires breaking RSA-2048 (computationally infeasible) |
| **Forward secrecy** | N/A (key visible anyway) | No (compromising RSA private key exposes past sessions). Would need ephemeral DH for forward secrecy. |
| **Session isolation** | All clients share one key | Each client generates its own AES-256 key |

**Handshake flow:**
```
BEFORE:                              AFTER:
Server → Client: AES_KEY (plain!)    Server → Client: RSA_PUBLIC_KEY (safe to expose)
                                     Client → Server: RSA_OAEP(AES_KEY) (only server can decrypt)
Both use AES_KEY                     Both use client-generated AES_KEY
```

### 2.3 RSA Padding: Why OAEP, Not PKCS#1 v1.5

| Property | PKCS#1 v1.5 | RSA-OAEP |
|----------|-------------|----------|
| **Padding structure** | Deterministic format: `0x00 0x02 [random] 0x00 [data]` | Two-round Feistel network with hash function + MGF |
| **Bleichenbacher's attack (1998)** | Vulnerable — attacker sends ~1 million modified ciphertexts, uses padding error responses to gradually decrypt | Not vulnerable — OAEP padding errors don't leak useful information |
| **Determinism** | Partially random, but structure is exploitable | Fully randomized — same plaintext → different ciphertext each time |
| **Security proof** | No proof of CCA2 security | Provably CCA2-secure (chosen-ciphertext attack resistant) under RSA assumption |
| **Standard recommendation** | Deprecated for new systems (NIST, IETF) | Recommended (PKCS#1 v2.2, NIST SP 800-56B) |

### 2.4 Password Storage: Plaintext vs. PBKDF2

| Property | Plaintext | PBKDF2-HMAC-SHA256 |
|----------|-----------|-------------------|
| **Storage** | `ADMIN_PASS = "secure123"` in source code | `ADMIN_PASS_HASH` (Base64 hash) + `ADMIN_SALT` (Base64 salt) |
| **If source code is leaked** | Attacker has the password immediately | Attacker has only the hash — must brute-force through 65536 HMAC-SHA256 iterations per guess |
| **Rainbow table attack** | Password found instantly in any rainbow table | 16-byte random salt makes pre-computed tables useless |
| **Brute-force cost** | 0 (password in plain sight) | ~65536× slower than raw SHA-256 per attempt |
| **Timing attack** | `String.equals()` exits on first mismatched character — attacker can deduce password length and characters by measuring response times | Constant-time XOR comparison — response time is identical regardless of how many characters match |

**PBKDF2 computation:**
```
password + salt → HMAC-SHA256 → iterate 65536 times → 256-bit derived key
```

### 2.5 Session Isolation: Shared Key vs. Per-Client Keys

| Property | Shared Key | Per-Client Keys |
|----------|-----------|----------------|
| **Key generation** | Server generates one `SecretKey` at startup | Each client generates its own `SecretKey` |
| **Compromise impact** | Breaking one session's key breaks ALL active sessions | Breaking one session's key affects only that session |
| **Key scope** | Static field shared across all `ClientHandler` threads | Local variable in `ClientHandler.run()` — thread-confined |
| **Concurrent clients** | All encrypt/decrypt with the same key | Each has an independent key — no crosstalk possible |

### 2.6 Brute-force Protection

| Property | Before | After |
|----------|--------|-------|
| **Login attempts** | Unlimited — attacker can try millions of passwords | 3 attempts per IP, then 30-second lockout |
| **Tracking** | None | `ConcurrentHashMap` per IP (thread-safe) |
| **Recovery** | N/A | Counter resets on successful login; lockout expires after 30s |
| **Client feedback** | Only "Access Denied" | `LOCKED_OUT` message with cooldown notification |

### 2.7 Minor Hardening

| Area | Before | After | Risk Mitigated |
|------|--------|-------|---------------|
| **Command logging** | `"Received command: " + command` | `"Received command from " + IP + " (" + length + " chars)"` | Information leakage — passwords or sensitive data in commands appearing in server logs |
| **Socket timeout** | None | 5-minute timeout (`setSoTimeout(300000)`) | Resource exhaustion DoS — idle connections consuming server threads/memory indefinitely |

---

## 3. Threat Model

| Threat | Old Vulnerability | New Mitigation | Residual Risk |
|--------|-------------------|----------------|---------------|
| **Network eavesdropping** | AES key sent in plaintext → all traffic decryptable | RSA-OAEP key exchange — key never in the clear | MITM could substitute RSA public key (no certificate pinning) |
| **Ciphertext pattern analysis** | ECB leaks block patterns | GCM with random IV — no patterns | None for this threat |
| **Ciphertext tampering** | No integrity check — modified ciphertext decrypts to garbage silently | GCM auth tag → `AEADBadTagException` on any modification | None for this threat |
| **Password theft from source** | Plaintext password in code | PBKDF2 hash + salt (65536 iterations) | Weak passwords still vulnerable to offline dictionary attacks |
| **Brute-force login** | Unlimited attempts | 3-attempt lockout per IP (30s cooldown) | Distributed attacks from many IPs; IP spoofing |
| **Timing attack on auth** | `String.equals()` is variable-time | Constant-time XOR comparison | None for this threat |
| **Session cross-contamination** | Shared AES key across all clients | Per-client unique session key | None for this threat |
| **Man-in-the-Middle (MITM)** | Trivial — intercept plaintext AES key | Harder — must substitute RSA public key | **Still possible** without certificate pinning or a PKI. Good academic discussion topic. |
| **Log information leakage** | Full commands logged in plaintext | Only IP + command length logged | None for this threat |
| **Resource exhaustion (DoS)** | No socket timeout | 5-minute timeout auto-closes idle connections | Attacker can still open many short-lived connections |

---

## 4. What's NOT Covered (Known Limitations)

These are intentional trade-offs for an academic project:

| Limitation | Why It Matters | Production Solution |
|-----------|---------------|-------------------|
| **No TLS** | Our custom protocol reimplements what TLS provides. TLS has been audited by millions of experts. | Use `SSLSocket` / `SSLServerSocket` |
| **No certificate pinning** | Client blindly trusts the RSA public key → MITM can substitute their own | Embed server's public key fingerprint in client, or use a CA-signed certificate |
| **No forward secrecy** | If the RSA private key is compromised, all past recorded sessions can be decrypted | Use ephemeral Diffie-Hellman (DHE/ECDHE) key exchange |
| **Single admin account** | No multi-user support | Database-backed user management |
| **No command restrictions** | Any system command can be executed | Whitelist/blacklist or sandboxing |
| **In-memory lockout state** | Server restart clears all lockout data | Persistent storage (file/database) |
| **No audit logging** | No persistent record of who did what | File-based or database audit trail |

---

## 5. Algorithms & Parameters Reference

| Component | Algorithm | Parameters |
|-----------|-----------|-----------|
| Symmetric encryption | AES-GCM | Key: 256-bit, IV: 12-byte (96-bit), Tag: 128-bit |
| Asymmetric encryption | RSA-OAEP | Key: 2048-bit, Hash: SHA-256, MGF: MGF1 |
| Password hashing | PBKDF2 | PRF: HMAC-SHA256, Iterations: 65,536, Output: 256-bit, Salt: 128-bit |
| Random number generation | `java.security.SecureRandom` | OS-provided entropy source |

---

## 6. References

- NIST SP 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)* 
- NIST SP 800-56B: *Recommendation for Pair-Wise Key-Establishment Using Integer Factorization Cryptography* (RSA-OAEP)
- NIST SP 800-132: *Recommendation for Password-Based Key Derivation* (PBKDF2)
- Bleichenbacher, D. (1998): *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS#1*
- PKCS#1 v2.2 (RFC 8017): RSA-OAEP specification
