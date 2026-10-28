#!/usr/bin/env python3
"""
nostr-batcher: generate batches of nostr keypairs (npub/nsec + hex) and export them.

No dependencies (Python 3.8+ standard library only). Secrets come from the OS
CSPRNG (secrets module). Pure-Python secp256k1, so it is slower than libsecp256k1
and NOT constant-time: use it on a machine you trust, not as a signing service.

    python3 nostr_batcher.py                      # interactive TUI ("TUI")
    python3 nostr_batcher.py -n 50 -f csv -o keys.csv
    python3 nostr_batcher.py -n 5 -f nsec         # five nsec lines on stdout
    python3 nostr_batcher.py -n 3 --prefix 42     # npub1 42... vanity keys
    python3 nostr_batcher.py --selftest

Formats: json, jsonl, csv, txt, npub, nsec
Key encoding (NIP-01 / NIP-19): the public key is the 32-byte x-only coordinate
of d*G on secp256k1 (BIP-340); npub/nsec are bech32 (not bech32m) of the raw 32 bytes.
"""
import argparse
import csv
import datetime
import io
import json
import os
import secrets
import sys
import time

# --------------------------------------------------------------------------
# secp256k1 (Jacobian coordinates, a = 0)
# --------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_INF = (0, 1, 0)
_G = (GX, GY, 1)


def _jdbl(p):
    X, Y, Z = p
    if Z == 0 or Y == 0:
        return _INF
    ysq = Y * Y % P
    S = 4 * X * ysq % P
    M = 3 * X * X % P
    X2 = (M * M - 2 * S) % P
    return (X2, (M * (S - X2) - 8 * ysq * ysq) % P, 2 * Y * Z % P)


def _jadd(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1s, Z2s = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2s % P, X2 * Z1s % P
    S1, S2 = Y1 * Z2 * Z2s % P, Y2 * Z1 * Z1s % P
    if U1 == U2:
        return _jdbl(p) if S1 == S2 else _INF
    H, R = (U2 - U1) % P, (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    V = U1 * H2 % P
    X3 = (R * R - H3 - 2 * V) % P
    return (X3, (R * (V - X3) - S1 * H3) % P, H * Z1 * Z2 % P)


def _mul_g(d):
    acc, base = _INF, _G
    while d:
        if d & 1:
            acc = _jadd(acc, base)
        base = _jdbl(base)
        d >>= 1
    return acc


def _affine_x(p):
    zi = pow(p[2], -1, P)
    return p[0] * zi * zi % P


def pubkey_x(d):
    """x-only public key (int) for secret scalar d, 1 <= d < N."""
    if not 1 <= d < N:
        raise ValueError("secret out of range")
    return _affine_x(_mul_g(d))


def rand_scalar():
    return secrets.randbelow(N - 1) + 1  # uniform in [1, N-1]


# --------------------------------------------------------------------------
# bech32 (BIP-173, constant 1) + NIP-19
# --------------------------------------------------------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]


def _convert(data, frm, to, pad):
    acc = bits = 0
    out, maxv = [], (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
        acc &= (1 << bits) - 1
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or (acc << (to - bits)) & maxv:
        raise ValueError("invalid padding")
    return out


def bech32_encode(hrp, data):
    d5 = _convert(data, 8, 5, True)
    pm = _polymod(_hrp_expand(hrp) + d5 + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[x] for x in d5 + chk)


def bech32_decode(s):
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("bad bech32 structure")
    try:
        data = [CHARSET.index(c) for c in s[pos + 1:]]
    except ValueError:
        raise ValueError("invalid bech32 character")
    hrp = s[:pos]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad checksum")
    return hrp, bytes(_convert(data[:-6], 5, 8, False))


# --------------------------------------------------------------------------
# key objects
# --------------------------------------------------------------------------
def make_key(d, x=None):
    if x is None:
        x = pubkey_x(d)
    priv, pub = d.to_bytes(32, "big"), x.to_bytes(32, "big")
    return {
        "npub": bech32_encode("npub", pub),
        "nsec": bech32_encode("nsec", priv),
        "pubkey_hex": pub.hex(),
        "privkey_hex": priv.hex(),
    }


class Cancelled(Exception):
    pass


def check_prefix(prefix):
    prefix = prefix.lower()
    bad = sorted({c for c in prefix if c not in CHARSET})
    if bad:
        raise ValueError("prefix has characters npub cannot contain: %s (allowed: %s)"
                         % (" ".join(bad), CHARSET))
    if len(prefix) > 6:
        raise ValueError("prefix longer than 6 characters is impractical")
    return prefix


def vanity(prefix, tick=None):
    """Find d such that npub1<prefix>... . Walks d0, d0+1, ... from a random d0
    (one point addition per try). Returns (d, x, attempts)."""
    want = 0
    for ch in prefix:
        want = (want << 5) | CHARSET.index(ch)
    shift = 256 - 5 * len(prefix)
    attempts = 0
    while True:
        d = rand_scalar()
        q = _mul_g(d)
        for _ in range(1 << 22):  # re-seed now and then
            attempts += 1
            x = _affine_x(q)
            if x >> shift == want:
                return d, x, attempts
            if tick and attempts % 2048 == 0 and not tick(attempts):
                raise Cancelled()
            q = _jadd(q, _G)
            d += 1
            if d >= N or q[2] == 0:
                break


def forge(count, prefix="", tick=None):
    """Generate `count` keys. tick(done, total, attempts) -> False cancels."""
    keys, attempts = [], 0
    for i in range(count):
        if prefix:
            base = attempts
            d, x, a = vanity(
                prefix,
                (lambda at: tick(i, count, base + at)) if tick else None)
            attempts += a
        else:
            d = rand_scalar()
            x = None
            attempts += 1
        keys.append(make_key(d, x))
        if tick and not tick(i + 1, count, attempts):
            raise Cancelled()
    return keys


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------
FORMATS = ("json", "jsonl", "csv", "txt", "npub", "nsec")
EXT = {"json": "json", "jsonl": "jsonl", "csv": "csv", "txt": "txt",
       "npub": "txt", "nsec": "txt"}
FIELDS = ("npub", "nsec", "pubkey_hex", "privkey_hex")


def render(keys, fmt):
    if fmt == "json":
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        return json.dumps({"generated": stamp, "count": len(keys), "keys": keys}, indent=2) + "\n"
    if fmt == "jsonl":
        return "".join(json.dumps(k) + "\n" for k in keys)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(keys)
        return buf.getvalue()
    if fmt == "txt":
        return "\n".join("# %d\nnpub: %s\nnsec: %s\npub hex:  %s\npriv hex: %s\n"
                         % (i + 1, k["npub"], k["nsec"], k["pubkey_hex"], k["privkey_hex"])
                         for i, k in enumerate(keys))
    if fmt in ("npub", "nsec"):
        return "".join(k[fmt] + "\n" for k in keys)
    raise ValueError("unknown format " + fmt)


def write_private(path, text, force=False):
    """Write with mode 0600; refuse to overwrite unless force."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if force:
        os.chmod(path, 0o600)


def default_name(fmt):
    return "nostr-batcher-%s.%s" % (time.strftime("%Y%m%d-%H%M%S"), EXT[fmt])


def vanity_estimate(prefix):
    return 32 ** len(prefix)


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------
def selftest():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("  ok   " if cond else "  FAIL ") + name)
        ok = ok and cond

    check("1*G x == G.x", pubkey_x(1) == GX)
    check("(N-1)*G has same x as G", pubkey_x(N - 1) == GX)
    check("2*G x", pubkey_x(2) == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5)
    check("3*G x", pubkey_x(3) == 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9)
    vec_hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    vec_npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
    check("NIP-19 npub vector encodes", bech32_encode("npub", bytes.fromhex(vec_hex)) == vec_npub)
    check("NIP-19 npub vector decodes", bech32_decode(vec_npub) == ("npub", bytes.fromhex(vec_hex)))
    try:
        bech32_decode(vec_npub[:-1] + ("q" if vec_npub[-1] != "q" else "p"))
        check("bad checksum rejected", False)
    except ValueError:
        check("bad checksum rejected", True)
    k = make_key(rand_scalar())
    check("random key round-trips (npub)", bech32_decode(k["npub"])[1].hex() == k["pubkey_hex"])
    check("random key round-trips (nsec)", bech32_decode(k["nsec"])[1].hex() == k["privkey_hex"])
    check("pubkey matches secret", pubkey_x(int(k["privkey_hex"], 16)) == int(k["pubkey_hex"], 16))
    d, x, _ = vanity("n")
    vk = make_key(d, x)
    check("vanity key starts npub1n", vk["npub"].startswith("npub1n"))
    check("vanity pubkey matches secret", pubkey_x(d) == x)
    batch = forge(5)
    check("batch has 5 unique keys", len({b["npub"] for b in batch}) == 5)
    print("selftest " + ("passed" if ok else "FAILED"))
    return ok


# --------------------------------------------------------------------------
# TUI
# --------------------------------------------------------------------------
def run_tui():
    import curses
    import locale
    import shutil
    import subprocess

    locale.setlocale(locale.LC_ALL, "")
    utf = (locale.getpreferredencoding() or "").lower().startswith("utf")
    MASK = "\u2022" if utf else "*"
    BAR_ON, BAR_OFF = ("\u2588", "\u2591") if utf else ("#", "-")
    MIN_H, MIN_W = 20, 74

    st = {"count": 10, "fmt": 0, "prefix": "", "keys": [], "sel": 0, "top": 0,
          "reveal": False, "saved": True, "msg": "press g to forge keys", "msg_kind": 0}

    def clip(text):
        for cmd in (["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-bi"]):
            if shutil.which(cmd[0]):
                subprocess.run(cmd, input=text.encode(), check=True)
                return cmd[0]
        return None

    def main(scr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        colors = curses.has_colors()
        if colors:
            curses.start_color()
            curses.use_default_colors()
            for i, c in enumerate((curses.COLOR_CYAN, curses.COLOR_GREEN, curses.COLOR_YELLOW,
                                   curses.COLOR_RED, curses.COLOR_MAGENTA), 1):
                curses.init_pair(i, c, -1)
        CY, GR, YE, RE, MA = [curses.color_pair(i) if colors else 0 for i in range(1, 6)]
        B, REV, DIM = curses.A_BOLD, curses.A_REVERSE, curses.A_DIM

        def put(y, x, s, attr=0):
            h, w = scr.getmaxyx()
            if 0 <= y < h and 0 <= x < w:
                try:
                    scr.addnstr(y, x, s, max(0, w - x - (1 if y == h - 1 else 0)), attr)
                except curses.error:
                    pass

        def short(s, n):
            return s if len(s) <= n else s[:n - 10] + "\u2026" + s[-9:] if utf else s[:n - 10] + "~" + s[-9:]

        def masked(s):
            return s[:5] + MASK * (len(s) - 5)

        def set_msg(text, kind=0):
            st["msg"], st["msg_kind"] = text, kind

        def draw(progress=None):
            scr.erase()
            h, w = scr.getmaxyx()
            if h < MIN_H or w < MIN_W:
                put(0, 0, "Terminal too small: need %dx%d (now %dx%d)" % (MIN_W, MIN_H, w, h), RE | B)
                scr.refresh()
                return
            put(0, 0, " NOSTR BATCHER ", REV | B | CY)
            put(0, 18, "secp256k1 \u00b7 BIP-340 x-only \u00b7 NIP-19 bech32" if utf
                else "secp256k1 / BIP-340 x-only / NIP-19 bech32", DIM)
            badge = " SECRETS VISIBLE " if st["reveal"] else " secrets hidden "
            put(0, w - len(badge) - 1, badge, (REV | B | RE) if st["reveal"] else (DIM))
            put(1, 0, (("\u2500" if utf else "-") * w), DIM)
            fmt = FORMATS[st["fmt"]]
            put(2, 1, "Count", DIM); put(2, 7, " %d " % st["count"], REV | B)
            put(2, 16, "Format", DIM); put(2, 23, " %s " % fmt, REV | B | GR)
            put(2, 33, "Vanity", DIM)
            pv = "npub1" + st["prefix"] if st["prefix"] else "off"
            put(2, 40, " %s " % pv, REV | B | (YE if st["prefix"] else 0))
            if st["prefix"]:
                put(3, 40, "~%s tries per key" % format(vanity_estimate(st["prefix"]), ","), DIM)
            put(2, 62, "keys: %d" % len(st["keys"]), DIM)
            put(4, 0, "  #  %-52s %s" % ("npub", "nsec"), B | DIM)
            list_h = h - 4 - 7 - 2
            keys = st["keys"]
            st["sel"] = max(0, min(st["sel"], len(keys) - 1))
            if st["sel"] < st["top"]:
                st["top"] = st["sel"]
            if st["sel"] >= st["top"] + list_h:
                st["top"] = st["sel"] - list_h + 1
            if not keys:
                put(6, 3, "No keys yet. g = forge %d key%s." % (st["count"], "" if st["count"] == 1 else "s"), DIM)
            for r in range(list_h):
                i = st["top"] + r
                if i >= len(keys):
                    break
                k = keys[i]
                y = 5 + r
                cur = i == st["sel"]
                base = REV if cur else 0
                put(y, 0, " " * w, base)
                put(y, 1, "%3d" % (i + 1), base | DIM)
                npub = short(k["npub"], 52)
                put(y, 5, "%-52s" % npub, base)
                if st["prefix"] and k["npub"].startswith("npub1" + st["prefix"]):
                    put(y, 5, "npub1" + st["prefix"], base | B | (GR if not cur else 0))
                ns = short(k["nsec"], 20) if st["reveal"] else masked(k["nsec"])[:20]
                put(y, 58, ns, base | (RE if st["reveal"] else DIM))
            if keys:
                put(5 + list_h - 1 if False else 5 + list_h, w - 14, "%d/%d" % (st["sel"] + 1, len(keys)), DIM)
            # detail panel
            dy = h - 8
            put(dy, 0, (("\u2500" if utf else "-") * w), DIM)
            if keys:
                k = keys[st["sel"]]
                put(dy + 1, 1, "npub", CY | B); put(dy + 1, 11, k["npub"])
                put(dy + 2, 1, "nsec", RE | B)
                put(dy + 2, 11, k["nsec"] if st["reveal"] else masked(k["nsec"]), RE if st["reveal"] else DIM)
                put(dy + 3, 1, "pub", DIM); put(dy + 3, 11, k["pubkey_hex"], DIM)
                put(dy + 4, 1, "priv", DIM)
                put(dy + 4, 11, k["privkey_hex"] if st["reveal"] else MASK * 64, DIM)
            if progress:
                done, total, attempts, rate = progress
                bw = 30
                fill = int(bw * done / max(1, total))
                put(dy + 5, 1, "[" + BAR_ON * fill + BAR_OFF * (bw - fill) + "] %d/%d  %s tries  %s/s   x = cancel"
                    % (done, total, format(attempts, ","), format(int(rate), ",")), YE | B)
            else:
                kind = (0, GR, RE)[st["msg_kind"]]
                put(dy + 5, 1, st["msg"], kind)
            hints = "g forge  +/- count  [ ] \u00b110  f format  p vanity  r reveal  e export  y/Y copy npub/nsec  q quit"
            put(h - 1, 0, hints[:w - 1], REV)
            scr.refresh()

        def prompt(label, default=""):
            buf = list(default)
            while True:
                h, w = scr.getmaxyx()
                dy = h - 8
                put(dy + 5, 0, " " * (w - 1))
                put(dy + 5, 1, label + ": " + "".join(buf) + "_", YE | B)
                scr.refresh()
                ch = scr.getch()
                if ch in (10, 13, curses.KEY_ENTER):
                    return "".join(buf)
                if ch == 27:
                    return None
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                elif 32 <= ch < 127:
                    buf.append(chr(ch))

        def do_forge():
            t0 = time.time()
            last = [0.0]
            scr.nodelay(True)

            def tick(done, total, attempts):
                ch = scr.getch()
                if ch in (27, ord("x"), ord("X")):
                    return False
                now = time.time()
                if now - last[0] > 0.1:
                    last[0] = now
                    draw((done, total, attempts, attempts / max(1e-6, now - t0)))
                return True

            try:
                keys = forge(st["count"], st["prefix"], tick)
                st["keys"], st["sel"], st["top"], st["saved"] = keys, 0, 0, False
                set_msg("forged %d key%s in %.1fs. Export with e before quitting." %
                        (len(keys), "" if len(keys) == 1 else "s", time.time() - t0), 1)
            except Cancelled:
                set_msg("cancelled", 2)
            finally:
                scr.nodelay(False)

        def do_export():
            if not st["keys"]:
                set_msg("nothing to export yet", 2)
                return
            fmt = FORMATS[st["fmt"]]
            name = prompt("save as (Enter = default, Esc = cancel)", default_name(fmt))
            if name is None:
                set_msg("export cancelled")
                return
            name = name.strip() or default_name(fmt)
            try:
                write_private(os.path.expanduser(name), render(st["keys"], fmt))
                st["saved"] = True
                set_msg("saved %d keys to %s (mode 0600, plaintext, keep it safe)" % (len(st["keys"]), name), 1)
            except FileExistsError:
                set_msg("%s already exists, choose another name" % name, 2)
            except OSError as e:
                set_msg("could not save: %s" % e.strerror, 2)

        while True:
            draw()
            ch = scr.getch()
            if ch == curses.KEY_RESIZE:
                continue
            if ch in (ord("q"), ord("Q")):
                if st["keys"] and not st["saved"]:
                    a = prompt("unsaved keys will be lost. quit? type y to confirm")
                    if a is None or a.strip().lower() != "y":
                        set_msg("quit cancelled")
                        continue
                return
            elif ch in (curses.KEY_UP, ord("k")):
                st["sel"] -= 1
            elif ch in (curses.KEY_DOWN, ord("j")):
                st["sel"] += 1
            elif ch == curses.KEY_PPAGE:
                st["sel"] -= 10
            elif ch == curses.KEY_NPAGE:
                st["sel"] += 10
            elif ch == curses.KEY_HOME:
                st["sel"] = 0
            elif ch == curses.KEY_END:
                st["sel"] = len(st["keys"]) - 1
            elif ch in (ord("+"), ord("=")):
                st["count"] = min(10000, st["count"] + 1)
            elif ch in (ord("-"), ord("_")):
                st["count"] = max(1, st["count"] - 1)
            elif ch == ord("]"):
                st["count"] = min(10000, st["count"] + 10)
            elif ch == ord("["):
                st["count"] = max(1, st["count"] - 10)
            elif ch in (ord("f"), ord("F")):
                st["fmt"] = (st["fmt"] + 1) % len(FORMATS)
            elif ch in (ord("r"), ord("R")):
                st["reveal"] = not st["reveal"]
            elif ch in (ord("p"), ord("P")):
                v = prompt("vanity prefix after npub1 (empty = off, max 4 here)", st["prefix"])
                if v is not None:
                    try:
                        v = check_prefix(v.strip())
                        if len(v) > 4:
                            raise ValueError("max 4 characters in the TUI")
                        st["prefix"] = v
                        set_msg("vanity prefix set" if v else "vanity off")
                    except ValueError as e:
                        set_msg(str(e), 2)
            elif ch in (ord("g"), ord("G")):
                do_forge()
            elif ch in (ord("e"), ord("E")):
                do_export()
            elif ch in (ord("y"), ord("Y")) and st["keys"]:
                k = st["keys"][st["sel"]]
                which = "nsec" if ch == ord("Y") else "npub"
                try:
                    tool = clip(k[which])
                    set_msg("%s copied via %s%s" % (which, tool, " (clipboard is visible to other apps)" if which == "nsec" else "")
                            if tool else "no clipboard tool found (pbcopy, wl-copy, xclip, xsel)", 1 if tool else 2)
                except Exception:
                    set_msg("clipboard copy failed", 2)

    curses.wrapper(main)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nostr_batcher.py",
        description="Generate batches of nostr keypairs. With no arguments on a terminal, opens the TUI.")
    ap.add_argument("-n", "--count", type=int, default=None, help="number of keys (default 1, max 10000)")
    ap.add_argument("-f", "--format", choices=FORMATS, default="json", help="output format (default json)")
    ap.add_argument("-o", "--output", help="write to file (mode 0600) instead of stdout")
    ap.add_argument("--force", action="store_true", help="overwrite the output file if it exists")
    ap.add_argument("--prefix", default="", help="vanity: npub must start with npub1<prefix> (max 6 chars; 4+ is slow)")
    ap.add_argument("--tui", action="store_true", help="open the interactive TUI")
    ap.add_argument("--selftest", action="store_true", help="run built-in test vectors and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        return 0 if selftest() else 1
    if args.tui or (argv is None and len(sys.argv) == 1 and sys.stdin.isatty() and sys.stdout.isatty()):
        run_tui()
        return 0

    count = 1 if args.count is None else args.count
    if not 1 <= count <= 10000:
        ap.error("--count must be between 1 and 10000")
    try:
        prefix = check_prefix(args.prefix)
    except ValueError as e:
        ap.error(str(e))

    show = sys.stderr.isatty() and bool(prefix)
    t0 = time.time()

    def tick(done, total, attempts):
        if show:
            sys.stderr.write("\r%d/%d keys, %s tries, %.0fs " % (done, total, format(attempts, ","), time.time() - t0))
            sys.stderr.flush()
        return True

    if prefix:
        print("vanity npub1%s: about %s tries per key" % (prefix, format(vanity_estimate(prefix), ",")), file=sys.stderr)
    try:
        keys = forge(count, prefix, tick if show else None)
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return 130
    if show:
        sys.stderr.write("\n")
    text = render(keys, args.format)
    if args.output:
        try:
            write_private(args.output, text, args.force)
        except FileExistsError:
            print("error: %s exists (use --force to overwrite)" % args.output, file=sys.stderr)
            return 1
        print("wrote %d keys to %s (mode 0600, plaintext)" % (len(keys), args.output), file=sys.stderr)
    else:
        if sys.stdout.isatty() and args.format != "npub":
            print("warning: private keys are being printed to the terminal", file=sys.stderr)
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
