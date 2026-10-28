# Natural Resources Certificate Monitor (`nr-cert-monitor`)

[![SSL Expiry Monitor](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml/badge.svg)](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml)

Declarative SSL/TLS certificate expiry monitor for Natural Resources production vanity URLs.

The monitor runs on a weekly schedule (and on demand via `workflow_dispatch`) to inspect TLS endpoints via SNI handshakes. If any certificate is approaching expiration or unreachable, an alert issue is automatically created or updated with current diagnostic details.

## Reports & Actions

- **Run Summaries & Dashboard**: Live certificate inspection summaries for every run are available directly on the [SSL Expiry Monitor Actions page](https://github.com/bcgov/nr-cert-monitor/actions/workflows/ssl-expiry.yml). Each run summary provides an at-a-glance table of all monitored domains, expiry dates, remaining days, and status, and highlights any created, updated, or resolved alert issues.
- **Alert Issues**: Certificate expiry breaches automatically create or update an idempotent issue assigning designated maintainers. Once a certificate is renewed/updated and healthy, the monitor automatically resolves and closes the issue.

## Configuration

All endpoints, thresholds, and issue parameters are defined in [`rules.yml`](rules.yml):

```yaml
technical:
  warning_days: 30     # Threshold in days before triggering an alert
  timeout_seconds: 10  # Hard timeout per TLS handshake
  port: 443            # Default TLS port

issue:
  title_prefix: "SSL Expiry: "
  labels:              # Optional; labels applied to alert issues
    - security
    - ssl-expiry

monitoring:
  domains:
    - host: "fom.nrs.gov.bc.ca"
      description: "Forest Operations Map"
      assignees:
        - DerekRoberts
    - host: "silva.nrs.gov.bc.ca"
      description: "Silva"
      assignees:
        - DerekRoberts
```

## Adding Your Application

Want your production vanity URL monitored? Open a Pull Request adding your service to [`rules.yml`](rules.yml) under `monitoring.domains`:

```yaml
    - host: "your-app.nrs.gov.bc.ca"
      description: "My Application Name"
      assignees:
        - yourGitHubHandle  # You or your team's designated on-call GitHub handles
```

### Requirements
- **Must be publicly reachable:** The engine inspects public vanity URLs via TLS SNI over port 443 from GitHub Actions runners.
- **Must provide assignees:** Every domain entry must specify a non-empty `assignees` list of GitHub usernames. Automated CI tests enforce this requirement on pull requests so alert issues notify the engineers who own the service.
