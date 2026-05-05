# SafeLog GitLab CI/CD Template

Include the template from this repository to run SafeLog in GitLab CI/CD.

```yaml
include:
  - local: "ci/gitlab/safelog.gitlab-ci.yml"

variables:
  SAFELOG_PATH: "logs/*.log"
  SAFELOG_FAIL_ON: "block"
```

## Variables

- `SAFELOG_PATH`: log file or basic shell glob to analyze. Default: `examples/sensitive.log`.
- `SAFELOG_FAIL_ON`: when the job should fail: `never`, `warn`, or `block`. Default: `block`.
- `SAFELOG_MAX_SIZE`: maximum log size before SafeLog exits with a file error. Default: `5MB`.
- `SAFELOG_REPORT_FORMAT`: report format to generate: `json`, `markdown`, or `both`. Default: `both`.

## Artifacts

The job always uploads `safelog-reports/` as an artifact with `when: always`.
Reports are produced by the SafeLog CLI inside the CI runner; raw logs are not sent to external services by SafeLog.
