# Log-Based Threat Detection System — Final Team Merge

This version combines the original project features with the useful additions found in the teammate ZIP.

## Included features
- Modern dark-themed GUI
- Log file parsing
- Built-in demo logs
- Rule-based threat detection
- URL/HTML normalization before detection
- Custom add/remove rules
- Severity filtering
- Failed-login counting and repeated-failed-login detection
- Top source-IP summary
- Desktop threat notifications
- Real-time log watching
- Threat Intelligence / local IOC lookup
- Optional AbuseIPDB lookup through `ABUSEIPDB_API_KEY`
- Automatic HIGH/CRITICAL block-list generation
- Security dashboard and chart
- PDF security report
- CSV alert export

## Run
```bash
pip install -r requirements.txt
python main.py
```

Use `sample_access.log` for testing.

## Team merge note
The teammate's project contributed the modern interface, demo-log loader, severity filtering, failed-login threshold detection, top source-IP summary, and Watch/Stop Watching workflow. Existing IOC, normalization, dashboard, notification, block-list, CSV and PDF features were retained.
