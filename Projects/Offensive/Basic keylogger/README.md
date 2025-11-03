## How it works (Python)

* Uses Tkinter GUI. The `Text` widget receives keystrokes when it has focus.
* `txt.bind("<Key>", log_event)` registers a handler called on each key press **inside that widget only**.
* The handler logs a timestamp, `keysym` (symbolic key name like `Return`, `a`, `Shift_L`), and `char` (actual character if any) to `local_key_events.log`.

## Run on Kali

```bash
python3 local_keylogger_tk.py
# Type into the app window, then inspect:
less local_key_events.log
```

This is safe: only keystrokes made in that GUI window are logged.



