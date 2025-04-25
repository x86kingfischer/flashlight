# FLASHLIGHT

**Simple, fast Windows tool to help catch what just flashed on your desktop.**  
Built to try learn more Rust, mistakes inevetable.

---

## What It Does

- Scans **recent process activity** from Windows Event Logs.
- Falls back to **Prefetch** artifacts if no logs found.
- Shows up to **10 of the most recent executable events**.
- Filters out noise like raw SIDs, empty entries, and junk PIDs.
- **Color-coded output** highlights potential suspicious actions.

---

## Features

- **Rust-native** — fast and standalone.
- **No background process** — run it once when you see something flash.
- **Zero install** — portable binary.
- **Eventlog + Prefetch fallback** — works even on systems with weak audit policies.
- **Readable, aligned console output**.

---

## Usage

Open an **Administrator terminal**, and just run:

```bash
flashlight.exe
```
---

## ❗ Requirements

- Windows 10 or 11
- Admin rights to read Security Event Logs
- Prefetch must be enabled (default on most systems)

---

## 🌟 Future Ideas (Planned)

- `--json` export mode
- `--watch` live polling
- `--alert` mode for suspicious process detection
- Lighter, no-admin fallback mode

---

## License

**MIT License** — Free to use, free to modify, attribution appreciated but not required.

---

## Personal Note

This project was built both to learn some Rust and to dismiss any paranoia after a terminal flashed on the desktop: 
If it helps you catch something weird, you're welcome.
