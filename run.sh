#!/bin/bash
# Clawditor daily audit runner.
# Runs collect -> reconcile -> digest sequentially.
# Called by launchd or manually.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

DATE=$(date +%Y%m%d)
LOG_DIR="$HOME/.clawditor/logs"
mkdir -p "$LOG_DIR"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Clawditor audit starting..." | tee "$LOG_DIR/run-$DATE.log"

# Step 1: Collect evidence
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Collecting evidence..." | tee -a "$LOG_DIR/run-$DATE.log"
python3 collect.py config.yaml 2>>"$LOG_DIR/run-$DATE.log" > /dev/null

EVIDENCE_FILE="$HOME/.clawditor/reports/evidence-$DATE.json"
if [ ! -f "$EVIDENCE_FILE" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: Evidence collection failed." | tee -a "$LOG_DIR/run-$DATE.log"
    exit 1
fi

# Step 2: Reconcile
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Reconciling sessions..." | tee -a "$LOG_DIR/run-$DATE.log"
python3 reconcile.py config.yaml "$EVIDENCE_FILE" 2>>"$LOG_DIR/run-$DATE.log" > /dev/null

AUDIT_FILE="$HOME/.clawditor/reports/audit-$DATE.json"
if [ ! -f "$AUDIT_FILE" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] WARNING: Reconciliation failed. Evidence saved." | tee -a "$LOG_DIR/run-$DATE.log"
    # Generate incomplete digest
    python3 -c "
import json, sys
audit = {'status': 'INCOMPLETE', 'error': 'Reconciliation failed. Raw evidence saved.', 'sessions': []}
json.dump(audit, sys.stdout)
" | python3 digest.py config.yaml 2>>"$LOG_DIR/run-$DATE.log"
    exit 0
fi

# Step 3: Generate digest
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Generating digest..." | tee -a "$LOG_DIR/run-$DATE.log"
python3 digest.py config.yaml "$AUDIT_FILE" 2>>"$LOG_DIR/run-$DATE.log"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Clawditor audit complete." | tee -a "$LOG_DIR/run-$DATE.log"
echo "Reports: $HOME/.clawditor/reports/"
