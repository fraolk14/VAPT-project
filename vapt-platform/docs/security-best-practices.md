# Security Best Practices

- Enforce RBAC everywhere and require `admin` or `analyst` roles for scan creation and asset mutation.
- Use OIDC or SAML SSO for workforce identity and keep local auth only for break-glass accounts.
- Enable MFA for privileged users and store MFA secrets in an encrypted secrets backend.
- Keep JWT secrets, scanner API keys, and database credentials in environment-backed secret managers.
- Segment scan engines from the primary control plane with strict network policies.
- Store audit logs immutably and forward them to Elasticsearch or a SIEM.
- Validate all inbound scan targets and uploaded files to prevent SSRF and malicious file execution.
- Run scanners with least privilege and isolate active testing workloads from the management plane.
- Apply OWASP ASVS controls to auth, session handling, logging, error messages, and access control.
- Sign desktop builds, enable auto-update verification, and pin outbound API endpoints.
- Map findings to CVSS, OWASP Top 10, and MITRE ATT&CK before exporting to downstream tools.
- Treat AI-based prioritization as advisory and preserve deterministic scoring alongside it.
