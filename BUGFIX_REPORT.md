# NetLogic Bug Fix Report

**Date:** 2026-08-19

This report documents bugs identified during a full codebase audit and the fixes applied.

---

## Summary

| Severity | Found | Fixed |
|----------|-------|-------|
| High     | 3     | 3     |
| Medium   | 5     | 5     |
| Low      | 4     | 4     |

The dashboard also received a professional UI refresh (sidebar layout, Inter typography, stat cards, split-panel login).

---

## High Severity

### 1. SaaS scan policy TOCTOU — unresolved hostnames bypassed restrictions
- **Location:** `api/scan_policy.py`
- **Problem:** When DNS lookup failed, hosted mode allowed any hostname.
- **Fix:** Fail-closed on unresolved hostnames; block `localhost` and loopback aliases.

### 2. `_scan_metrics` double-counted vulnerabilities
- **Location:** `api/routes/jobs.py`
- **Problem:** Counted raw `vuln` events and fusion rows together.
- **Fix:** Use fusion as sole source when fusion events exist.

### 3. React Rules of Hooks violation in ScanDetail
- **Location:** `dashboard/src/pages/ScanDetail.tsx`
- **Fix:** Hooks run unconditionally; `useJob` uses `enabled: !!jobId`.

---

## Medium Severity

### 4. Agent could complete a queued job → `api/routes/agents.py`
### 5. SSE reconnect duplicated events → `dashboard/src/api/scan.ts`
### 6. Target timeline Tailwind purge → `dashboard/src/pages/TargetTimeline.tsx`
### 7. Timeline metrics wrong (fixed via #2)
### 8. No retry for technical analysis errors → `ScanDetail.tsx`

---

## Low Severity

### 9. Disabled agents counted as online → `Dashboard.tsx`
### 10. Phase Test checkbox desync → `NewScan.tsx`
### 11. Targets hid in-progress scans → `Targets.tsx`
### 12. `useJob('')` fetched invalid endpoint → `scan.ts`

---

## UI Improvements

- Sidebar navigation with persistent New Scan CTA
- Inter + JetBrains Mono typography
- Refined palette, panel shadows, stat cards
- Split-panel login with product value props
- Consistent page headers and data tables

---

## Verification

- `1704` Python tests passing
- Dashboard production build successful
