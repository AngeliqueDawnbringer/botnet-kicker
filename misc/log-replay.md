# Log Replay Script (Dumb Replayer)

This script replays logs from an input file into a target logfile at a controlled pace.  
The idea is to **simulate incoming traffic** so monitoring and detection tooling can "learn"  
and react as if logs were being generated live.

---

## The Script

```bash
awk '
{
    print $0 >> "apache2/access.log"
    fflush("apache2/access.log")
    if (NR % 10 == 0) {
        system("sleep 1")
    }
}' output.txt
```

---

## How It Works

1. Reads lines from `output.txt` (your saved logs).  
2. Writes each line into `apache2/access.log`.  
3. Flushes output so it becomes visible to tools immediately.  
4. Every 10 lines, sleeps for 1 second before continuing.  

This creates a crude "real-time replay" of past logs.

---

## Tuning

- **Lines per interval**:  
  The `if (NR % 10 == 0)` controls how many lines are written before sleeping.  
  Change `10` to any number you like:  
  - `10` → write 10 lines per second  
  - `1000` → write 1000 lines per second  

- **Sleep interval**:  
  Currently hardcoded to `sleep 1`.  
  Change to `sleep 2` for a slower replay or remove entirely for a faster one.

---

## Example Usage

Replay logs at 100 lines per second:

```bash
awk '
{
    print $0 >> "apache2/access.log"
    fflush("apache2/access.log")
    if (NR % 100 == 0) {
        system("sleep 1")
    }
}' access-dump.txt
```

---

## Notes

- This is intentionally **dumb and simple**.  
- Useful for testing detection pipelines (e.g., SIEM, IDS, WAF learning).  
- Not accurate timing-wise; just bursts lines in chunks.  
- Make sure the target file (`apache2/access.log`) exists and has correct permissions.  
- Don’t use in production environments – it will **pollute real logs**.  

---

## License

Public domain / MIT – use at your own risk.
