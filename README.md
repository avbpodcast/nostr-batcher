# nostr-batcher

Generate batches of nostr keypairs (npub / nsec, plus hex) and export them. Two flavours: a single-file offline HTML page and a dependency-free Python CLI/TUI. Nothing is uploaded.

- **`nostr-batcher.html`**: open in a browser. Content-Security-Policy (`connect-src 'none'`) blocks all network connections.
- **`nostr_batcher.py`**: Python 3.8+, standard library only. Secrets come from the OS CSPRNG. Pure-Python secp256k1: slower than libsecp256k1 and not constant-time, so use it on a machine you trust, not as a signing service.
- **Formats**: json, jsonl, csv, txt, npub, nsec. Optional vanity prefix for npubs.

## Use

```
python3 nostr_batcher.py                       # interactive TUI
python3 nostr_batcher.py -n 50 -f csv -o keys.csv
python3 nostr_batcher.py -n 3 --prefix 42      # npub1 42... vanity keys
python3 nostr_batcher.py --selftest
```

Exported files contain secret keys. Store them like passwords.

## Verify the download

```
sha256sum -c SHA256SUMS
```

## Value-4-Value

This tool is free to use, no ads, no tracking. It runs on the Value-4-Value model: if it saved you time, give back what it was worth to you at https://allesvoorbitcoin.be/donate

## License

MIT, see [LICENSE](LICENSE).
