# Exercise 1: Safe ICS Reconnaissance

## Learning Objectives
- Understand Modbus/TCP protocol basics
- Perform safe network reconnaissance
- Identify exposed ICS endpoints

## Steps

1. Start the lab environment
2. Run safe scanner: `python attacks/recon_safe.py 172.20.0.10`
3. Analyze results for exposed unit IDs and registers
4. Document findings in JSON format

## Expected Output
```json
{
  "target": "172.20.0.10:5020",
  "unit_ids": [1],
  "holding_registers": {
    "1": [0, 100, 250, 0, 0, 0, 0, 0, 0, 0]
  }
}
