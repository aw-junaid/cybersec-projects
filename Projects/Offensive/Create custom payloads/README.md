# 1. What this tool is about

A **modular payload generator** that produces various harmless payloads for testing and detection:

* Template payloads (e.g., benign HTTP-like requests, JSON documents, CSV rows) for parser testing.
* Fuzz payloads (random bytes, long repeated patterns, unicode edge cases) to test input handling and IDS signatures.
* Binary patterns and sized blobs (zeroes, 0xFFs, incrementing bytes) to test file parsers/storage.
* Encoders/formatters (hex, base64, gzip) and output formats (raw file, hex dump, JSON manifest).
* Plugin architecture: add custom *benign* template modules without touching core.

Uses:

* Feed a WAF / IDS in a lab to validate detection rules.
* Generate test files for parsers (PDF/XML/JSON) — but **not** real exploit content.
* Create corpora for performance / robustness tests.

# General tool algorithm

```
Initialize configuration (output dir, selected module(s), count, sizes, encodings)

Load available payload modules (built-in modules like: template, fuzz, pattern, protocol-mock)

For each requested payload:
    - Choose module and parameters (size, randomness seed, template values, repetition)
    - Generate payload bytes (function should only use safe, non-executable content)
    - Optionally post-process:
         - encode (hex/base64)
         - compress (gzip)
         - wrap in a container (JSON record with metadata)
    - Save to file (raw) or emit to stdout / manifest
    - Log metadata: module, parameters, filename, timestamp, checksum
End

Provide simple plugin API so new modules can be added as pure generators returning bytes.
```

# How to run (Python)

1. Make file executable: `chmod +x safe_payload_generator.py`
2. Run examples:

   * Generate 5 random printable fuzz payloads, each 256 bytes:

     ```
     python3 safe_payload_generator.py -m fuzz -c 5 -P size=256 -o ./out_fuzz
     ```
   * Generate a gzip-compressed pattern of incrementing bytes (1024 bytes):

     ```
     python3 safe_payload_generator.py -m pattern -c 1 -P pattern=inc -P size=1024 -o ./out_pattern -e gzip
     ```
   * Generate 3 HTTP-like template payloads:

     ```
     python3 safe_payload_generator.py -m http -c 3 -P method=POST -P body="test body" -o ./out_http
     ```
3. Inspect `./out_*` folder and `manifest.json`. Open payloads with a hex viewer or Wireshark if wrapped into PCAPs later (we can add PCAP export).


# How to compile and run (C)

1. Compile:

   ```
   gcc safe_payload_generator.c -o safe_payload_generator
   ```
2. Run:

   * Pattern incrementing bytes:

     ```
     ./safe_payload_generator pattern 1024 2 ./out
     ```
   * Fuzz:

     ```
     ./safe_payload_generator fuzz 512 5 ./out
     ```

Note: this minimal C example uses a placeholder for SHA256 to keep the code small. For production-grade manifests compute real checksums (use OpenSSL or libsodium). The C program is intentionally conservative (no network, no shellcode).
