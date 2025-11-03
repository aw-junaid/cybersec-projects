#!/usr/bin/env python3
"""
local_keylogger_tk.py

Safe, educational demo: logs keys typed into this window only.
Does NOT capture system-wide keystrokes.

This is a security-conscious keylogger that only captures keystrokes
within its own application window, making it safe for educational purposes.
"""

import tkinter as tk
from datetime import datetime

# File where key events will be logged
LOGFILE = "local_key_events.log"

def log_event(e):
    """
    Callback function that handles key press events.
    
    Args:
        e: The key event object containing information about the key pressed
    """
    # Get current timestamp in ISO format with UTC timezone
    ts = datetime.utcnow().isoformat() + "Z"
    
    # Create log entry with timestamp, keysym (symbolic key name), and char (actual character)
    # Using !r to get the representation (includes quotes and escape sequences)
    entry = f"{ts}  keysym={e.keysym!r}  char={e.char!r}\n"
    
    # Append the log entry to file
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(entry)
    
    # Update the status display in the UI
    status_var.set(f"Last key: {e.keysym} (char: {e.char!r})")

# Create the main application window
root = tk.Tk()
root.title("Safe Key Event Logger — input must be in this window")

# String variable to display status updates
status_var = tk.StringVar(value="Type in the text box. Events logged to local_key_events.log")

# Create and pack UI elements

# Instruction label
label = tk.Label(root, text="Type here (only keystrokes in this app are logged):")
label.pack(padx=12, pady=(12,0))

# Text area where user can type - this is where key events are captured
txt = tk.Text(root, width=60, height=12)
txt.pack(padx=12, pady=8)
txt.focus_set()  # Set focus so user can start typing immediately

# Bind the key press event to our logging function
# The <Key> event fires for any key press in the Text widget
txt.bind("<Key>", log_event)

# Status label to show feedback
status = tk.Label(root, textvariable=status_var, anchor="w")
status.pack(fill="x", padx=12, pady=(0,12))

# Start the Tkinter event loop
root.mainloop()
