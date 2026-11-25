"""
Weak-code detector: insecure primitives actually exercised at runtime.

This complements the *static* ``crypto_scanner`` by reporting what the binary
really calls while executing, which removes the dead-code false positives a
static constant scan produces:

* **Weak crypto** — calls to broken/legacy primitives (MD5, MD4, SHA-1, DES,
  RC4, RC2) and ECB-mode ciphers (CWE-327/328).
* **Weak/predictable RNG** — ``srand`` seeded from ``time()`` or a constant,
  and use of ``rand``/``random`` where a CSPRNG is expected (CWE-338/330).
* **Weak authentication comparison** — a tainted value compared against a
  fixed secret with ``strcmp``/``memcmp`` (non-constant-time; CWE-208), the
  shape of a hardcoded-credential or token check.
"""

from __future__ import annotations

from .base import Detector
from ._shadow import TaintTracker
from ..events import CallEvent, RetEvent, TaintSourceEvent, HIGH, MEDIUM, LOW

# explicit weak-crypto symbols -> (algorithm, severity, cwe)
_WEAK_CRYPTO = {}


def _reg(names, algo, sev, cwe):
    for n in names:
        _WEAK_CRYPTO[n.lower()] = (algo, sev, cwe)


_reg(["md5", "md5_init", "md5_update", "md5_final", "evp_md5"], "MD5", MEDIUM, "CWE-327")
_reg(["md4", "md4_init", "evp_md4"], "MD4", MEDIUM, "CWE-327")
_reg(["sha1", "sha1_init", "sha1_update", "sha1_final", "evp_sha1"], "SHA-1", MEDIUM, "CWE-328")
_reg(["des_set_key", "des_set_key_checked", "des_ecb_encrypt", "des_ncbc_encrypt",
      "des_cbc_encrypt", "des_crypt", "evp_des_cbc", "evp_des_ecb", "evp_des_cfb",
      "evp_des_ofb"], "DES", HIGH, "CWE-327")
_reg(["rc4", "rc4_set_key", "evp_rc4", "arcfour"], "RC4", HIGH, "CWE-327")
_reg(["rc2", "evp_rc2_cbc", "evp_rc2_ecb"], "RC2", MEDIUM, "CWE-327")
_reg(["crypt"], "DES crypt()", MEDIUM, "CWE-916")

_RNG_INSECURE = {"rand", "random", "rand_r", "random_r"}
_RNG_SEED = {"srand", "srandom"}
_TIME_FUNCS = {"time", "gettimeofday", "clock", "times", "time64"}
_CMP_FUNCS = {"strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp"}


class WeakCodeDetector(Detector):
    category = "weak_code"

    def __init__(self) -> None:
        super().__init__()
        self.tracker = TaintTracker()
        self._reported = set()
        self._recent_time = False  # a time() call happened since the last srand

    def on_source(self, ev: TaintSourceEvent) -> None:
        self.tracker.source(ev)

    def on_ret(self, ev: RetEvent) -> None:
        self.tracker.ret(ev)

    def on_call(self, ev: CallEvent) -> None:
        name = (ev.name or "").lstrip("_")
        n = name.lower()
        self.tracker.call(ev, self.ctx.read_cstring)

        # weak crypto (explicit names, then ECB substring)
        if n in _WEAK_CRYPTO:
            algo, sev, cwe = _WEAK_CRYPTO[n]
            self._crypto(ev, name, algo, sev, cwe)
        elif "ecb" in n:
            self._crypto(ev, name, "ECB-mode cipher", MEDIUM, "CWE-327")

        # weak RNG
        if n in _TIME_FUNCS:
            self._recent_time = True
        elif n in _RNG_SEED:
            self._seed(ev, name)
        elif n in _RNG_INSECURE:
            self._raise(
                ("rng", n), title=f"Insecure PRNG: {name}()",
                description=f"{name}() is not a CSPRNG; unsafe for keys, tokens, "
                            f"nonces or session IDs.",
                severity=LOW, vuln_type="weak_rng", cwe="CWE-338",
                pc=ev.pc, function=name, confidence=0.5,
                evidence=f"{name}() at pc=0x{ev.pc:x}",
                remediation="Use a CSPRNG (/dev/urandom, getrandom()).",
            )

        # weak auth comparison
        if n in _CMP_FUNCS and len(ev.args) >= 2:
            self._auth_cmp(ev, name)

    # -- handlers -------------------------------------------------------------
    def _crypto(self, ev: CallEvent, name, algo, sev, cwe) -> None:
        self._raise(
            ("crypto", algo), title=f"Weak cryptography: {algo}",
            description=f"{name}() uses {algo}, which is broken or deprecated "
                        f"for security use.",
            severity=sev, vuln_type="weak_crypto", cwe=cwe,
            pc=ev.pc, function=name, confidence=0.8,
            evidence=f"call to {name}() at pc=0x{ev.pc:x}",
            remediation="Use modern primitives (SHA-256+, AES-GCM/ChaCha20).",
        )

    def _seed(self, ev: CallEvent, name) -> None:
        seed = ev.args[0] if ev.args else None
        predictable = self._recent_time or (seed is not None and seed < 0x10000)
        self._recent_time = False
        if predictable:
            why = "seeded from time()" if seed is None or seed >= 0x10000 \
                else f"seeded with constant 0x{seed:x}"
            self._raise(
                ("seed", ev.pc), title=f"Predictable PRNG seed via {name}()",
                description=f"{name}() {why}; the PRNG stream is predictable, "
                            f"so any keys/tokens derived from it are guessable.",
                severity=MEDIUM, vuln_type="weak_rng", cwe="CWE-337",
                pc=ev.pc, function=name, confidence=0.7,
                evidence=f"{name}({'time()' if seed is None else hex(seed)})",
                remediation="Seed from a CSPRNG, or use getrandom() directly.",
            )

    def _auth_cmp(self, ev: CallEvent, name) -> None:
        a, b = ev.args[0], ev.args[1]
        ta = self.tracker.tainted_ptr(a, self.ctx.read_cstring)
        tb = self.tracker.tainted_ptr(b, self.ctx.read_cstring)
        if bool(ta) == bool(tb):
            return  # need exactly one tainted operand (user input vs. secret)
        secret_ptr = b if ta else a
        secret = self.ctx.read_cstring(secret_ptr, 64)
        # heuristic: the fixed operand looks like a credential/token
        if not secret or len(secret) < 3 or not _looks_secretish(secret):
            return
        self._raise(
            ("auth", ev.pc), title=f"Credential check via {name}()",
            description=f"User-tainted input is compared against a fixed value "
                        f"with {name}() — non-constant-time and, if the fixed "
                        f"value is a secret, a hardcoded credential check.",
            severity=MEDIUM, vuln_type="auth_bypass", cwe="CWE-208",
            pc=ev.pc, function=name, confidence=0.5,
            evidence=f"{name}(tainted, {secret[:24]!r})",
            remediation="Compare secrets in constant time; never hardcode "
                        "credentials — verify a salted hash instead.",
        )

    def _raise(self, key, **kw) -> None:
        if key in self._reported:
            return
        self._reported.add(key)
        self._add(**kw)


def _looks_secretish(data: bytes) -> bool:
    try:
        s = data.decode("latin-1")
    except Exception:
        return False
    if any(c.isspace() for c in s):
        return False
    kw = ("pass", "pwd", "admin", "root", "key", "token", "secret", "login")
    low = s.lower()
    if any(k in low for k in kw):
        return True
    # mixed alnum of credential-ish length
    return 5 <= len(s) <= 40 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)
