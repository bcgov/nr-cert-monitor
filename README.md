# Natural Resources Certificate Monitor (`nr-cert-monitor`)

[![SSL Expiry Monitor](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml/badge.svg)](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml)

Declarative SSL/TLS certificate expiry monitor for Natural Resources production vanity URLs.

The monitor runs on a weekly schedule (and on demand via `workflow_dispatch`) to inspect TLS endpoints via SNI handshakes. If any certificate is approaching expiration or unreachable, an alert issue is automatically created or updated with current diagnostic details.

## Reports & Actions

- **Run Summaries & Dashboard**: Live certificate inspection summaries for every run are available directly on the [SSL Expiry Monitor Actions page](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml). Each run summary provides an at-a-glance table of all monitored domains, expiry dates, remaining days, and status.
- **Alert Issues**: Certificate expiry breaches automatically create an idempotent issue assigning designated maintainers.

## Configuration

All endpoints, thresholds, and issue parameters are defined in [`rules.yml`](rules.yml):

```yaml
technical:
  warning_days: 30     # Threshold in days before triggering an alert
  timeout_seconds: 10  # Hard timeout per TLS handshake
  port: 443            # Default TLS port

issue:
  title_prefix: "SSL Expiry: "
  assignees:
    - DerekRoberts
  labels:              # Optional; labels applied to alert issues
    - security
    - ssl-expiry

monitoring:
  domains:
    - host: "fom.nrs.gov.bc.ca"
      description: "Forest Operations Map"
      assignees:           # Optional per-domain override; defaults to issue.assignees
        - DerekRoberts
        - fomLeadDev
    - host: "silva.nrs.gov.bc.ca"
      description: "Silva"
```
