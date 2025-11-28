# ICS Security Research Lab

## SAFETY NOTICE

**THIS LAB MUST BE COMPLETELY ISOLATED FROM PRODUCTION NETWORKS**

- Never connect to real ICS/OT systems
- Operate only in air-gapped environments  
- Obtain written authorization before use
- Follow all local security policies

## Quick Start

1. Verify isolation: `python scripts/safety/check_isolated.py`
2. Start lab: `cd lab && docker-compose up -d`
3. Run safe reconnaissance: `python attacks/recon_safe.py 172.20.0.10`
4. View dashboard: http://172.20.0.14
5. Shutdown: `./scripts/safety/lab_kill_all.sh`

## Architecture

- **PLC Simulators**: Modbus/TCP servers (172.20.0.10-11)
- **OPC UA Simulator**: Industrial protocol simulation (172.20.0.12)  
- **HMI Dashboard**: Web interface (172.20.0.14)
- **Monitoring**: Prometheus + Grafana (172.20.0.15-16)
- **Attacker VM**: Isolated testing container (172.20.0.100)

## Lab Exercises

See `docs/exercises/` for training materials.
