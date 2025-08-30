# JWT Security Task - Deliverables

## Files included
- `jwt_attack_demo.py` : Python script demonstrating JWT attacks (weak secret forging, alg=none simulation).
- `report.pdf`         : 1-2 page research report on JWT vulnerabilities (PDF).
- `README.md`          : This file (setup & testing instructions).

## Requirements
- Python 3.8+ (recommended)
- No external packages required to run the demo script.
  - The demo uses only Python standard library functions.

## How to run the demo
1. Open a terminal.
2. Navigate to the directory containing the files.
   ```bash
   cd jwt_security_task
   ```
3. Run the demo script:
   ```bash
   python3 jwt_attack_demo.py
   ```
4. Observe the printed steps showing:
   - A token issued with a weak secret.
   - An attacker forging a token by signing with the same weak secret.
   - An alg=none token and verification when the verifier allows alg=none.

## What the demo shows
- **Weak-secret forging**: If a service uses a short or guessable secret (e.g., `secret`), an attacker can generate valid tokens by signing them with that secret.
- **alg=none**: Some flawed verifiers accept `alg=none` and treat tokens as valid without signature checks.
- **Key confusion (explained in output)**: Switching algorithms (RS256 <-> HS256) can allow attackers to misuse keys.

## PoC scope & limitations (be explicit)
- This is a local, educational PoC. It **does not** attack or interact with external servers.
- The script includes a deliberately-vulnerable `naive_verify` function to demonstrate how verifiers can be misconfigured.
- The report (`report.pdf`) covers recommendations and references to fix each vulnerability.

