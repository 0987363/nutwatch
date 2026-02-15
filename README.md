# nutwatch

`nutwatch` is a small Python watcher that reads UPS data from the NUT network interface and runs commands based on YAML-configured battery thresholds.

## Features

- Read UPS variables from NUT TCP service (`host:port`, default `3493`)
- Configure multiple threshold rule sets
- Execute multiple commands for each rule
- Run as a `systemd` service

## Files

- `nutwatch.py`: main watcher script
- `config.example.yaml`: configuration example
- `systemd/nutwatch.service`: systemd service template
- `requirements.txt`: Python dependencies

## Quick Start

1. Install dependency:

```bash
pip3 install -r requirements.txt
```

2. Copy and edit config:

```bash
cp config.example.yaml /etc/nutwatch/config.yaml
```

3. Run manually:

```bash
python3 nutwatch.py --config /etc/nutwatch/config.yaml
```

4. Dry-run test (only log commands, no execution):

```bash
python3 nutwatch.py --config /etc/nutwatch/config.yaml --dry
```

## Troubleshooting

If you see `ERR UNKNOWN-UPS`, your `nut.ups_name` is incorrect. List valid names on the NUT server:

```bash
upsc -l 127.0.0.1
```

Then update `ups_name` in your YAML config.

## Install with systemd

1. Copy files:

```bash
mkdir -p /opt/nutwatch /etc/nutwatch
cp nutwatch.py /opt/nutwatch/nutwatch.py
cp config.example.yaml /etc/nutwatch/config.yaml
cp systemd/nutwatch.service /etc/systemd/system/nutwatch.service
chmod +x /opt/nutwatch/nutwatch.py
```

2. Enable and start:

```bash
systemctl daemon-reload
systemctl enable --now nutwatch
```

3. View logs:

```bash
journalctl -u nutwatch -f
```

## Rule Fields

- `name`: rule name
- `var`: NUT variable name, e.g. `battery.charge`
- `operator`: `<`, `<=`, `>`, `>=`, `==`, `!=` (or aliases `lt/lte/gt/gte/eq/ne`)
- `threshold`: numeric threshold
- `trigger`: `on_enter` (fire once when condition becomes true) or `always` (fire every poll while true)
- `cooldown_seconds`: minimum interval between triggers
- `commands`: command list (string or object with `cmd`)

Command object optional fields:

- `shell` (bool)
- `timeout_seconds` (float)
- `continue_on_error` (bool)
- `env` (key-value map)
