from sqlalchemy import text

from app.database import engine


def ensure_runtime_schema() -> None:
    statements = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id INTEGER",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS group_name VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_user_agent TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_delivery_method VARCHAR NOT NULL DEFAULT 'totp'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_mfa_code VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_mfa_expires_at TIMESTAMPTZ",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS hostname VARCHAR",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS ip_address VARCHAR",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS url VARCHAR",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_type VARCHAR",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_level VARCHAR NOT NULL DEFAULT 'Medium'",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS classification VARCHAR NOT NULL DEFAULT 'Internal'",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_scan_id INTEGER",
        """
        CREATE TABLE IF NOT EXISTS user_groups (
            id VARCHAR PRIMARY KEY,
            name VARCHAR NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id UUID PRIMARY KEY,
            user_id VARCHAR NOT NULL REFERENCES users(id),
            session_token VARCHAR NOT NULL UNIQUE,
            device_name VARCHAR,
            ip_address VARCHAR,
            user_agent TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sso_providers (
            id UUID PRIMARY KEY,
            name VARCHAR NOT NULL,
            provider_type VARCHAR NOT NULL,
            login_url VARCHAR NOT NULL,
            metadata_url VARCHAR,
            client_id VARCHAR,
            client_secret TEXT,
            token_url VARCHAR,
            userinfo_url VARCHAR,
            scope VARCHAR,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS client_id VARCHAR",
        "ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS client_secret TEXT",
        "ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS token_url VARCHAR",
        "ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS userinfo_url VARCHAR",
        "ALTER TABLE sso_providers ADD COLUMN IF NOT EXISTS scope VARCHAR",
        """
        CREATE TABLE IF NOT EXISTS auth_policies (
            id UUID PRIMARY KEY,
            policy_name VARCHAR NOT NULL UNIQUE,
            captcha_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
            sso_required BOOLEAN NOT NULL DEFAULT FALSE,
            allow_local_login BOOLEAN NOT NULL DEFAULT TRUE,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_auth_sessions_session_token ON auth_sessions (session_token)",
        """
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id UUID PRIMARY KEY,
            job_name VARCHAR NOT NULL,
            scan_type VARCHAR NOT NULL,
            tool VARCHAR NOT NULL,
            target VARCHAR NOT NULL,
            profile VARCHAR NOT NULL DEFAULT 'standard',
            cadence_minutes VARCHAR NOT NULL DEFAULT '60',
            options JSON NOT NULL DEFAULT '{}'::json,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            last_run_at TIMESTAMPTZ,
            next_run_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_scheduled_scans_job_name ON scheduled_scans (job_name)",
        """
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL DEFAULT 'Unnamed Scan',
            engine VARCHAR NOT NULL DEFAULT 'Network',
            target VARCHAR NOT NULL,
            target_type VARCHAR NOT NULL DEFAULT 'IP',
            status VARCHAR NOT NULL DEFAULT 'PENDING',
            progress INTEGER NOT NULL DEFAULT 0,
            scheduled_at TIMESTAMPTZ,
            schedule_interval VARCHAR,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            asset_id UUID REFERENCES assets(id),
            user_id VARCHAR REFERENCES users(id)
        )
        """,
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS assigned_to VARCHAR",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS team_name VARCHAR",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS sla_due_at TIMESTAMPTZ",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification_state VARCHAR NOT NULL DEFAULT 'pending'",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS scan_job_id INTEGER",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS owner_id VARCHAR",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_recommendation TEXT",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS verification_status VARCHAR DEFAULT 'UNVERIFIED'",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS details TEXT",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS target VARCHAR",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS target_type VARCHAR",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS cve VARCHAR",
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            actor VARCHAR NOT NULL,
            action VARCHAR NOT NULL,
            resource_type VARCHAR NOT NULL,
            resource_id VARCHAR NOT NULL,
            outcome VARCHAR NOT NULL DEFAULT 'success',
            details JSON NOT NULL DEFAULT '{}'::json,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_resource ON audit_logs (resource_type, resource_id)",
        "CREATE INDEX IF NOT EXISTS ix_audit_logs_actor ON audit_logs (actor)",
        """
        CREATE TABLE IF NOT EXISTS false_positive_rules (
            id UUID PRIMARY KEY,
            title_pattern VARCHAR NOT NULL,
            cve_id VARCHAR,
            source VARCHAR,
            reason TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_false_positive_rules_title_pattern ON false_positive_rules (title_pattern)",
        "CREATE INDEX IF NOT EXISTS ix_false_positive_rules_cve_id ON false_positive_rules (cve_id)",
        "CREATE INDEX IF NOT EXISTS ix_false_positive_rules_source ON false_positive_rules (source)",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id VARCHAR NOT NULL DEFAULT 'default'",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS url VARCHAR",
        """
        CREATE TABLE IF NOT EXISTS alert_rules (
            id UUID PRIMARY KEY,
            name VARCHAR NOT NULL,
            channel VARCHAR NOT NULL,
            destination VARCHAR NOT NULL,
            min_severity VARCHAR NOT NULL DEFAULT 'high',
            scan_tool VARCHAR,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            metadata_json JSON NOT NULL DEFAULT '{}'::json,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS alert_events (
            id UUID PRIMARY KEY,
            rule_name VARCHAR NOT NULL,
            channel VARCHAR NOT NULL,
            destination VARCHAR NOT NULL,
            finding_id VARCHAR,
            status VARCHAR NOT NULL DEFAULT 'queued',
            payload JSON NOT NULL DEFAULT '{}'::json,
            response_message TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_alert_rules_name ON alert_rules (name)",
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id VARCHAR PRIMARY KEY,
            name VARCHAR NOT NULL UNIQUE,
            slug VARCHAR NOT NULL UNIQUE,
            status VARCHAR NOT NULL DEFAULT 'active',
            settings JSON NOT NULL DEFAULT '{}'::json,
            is_default BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS monitoring_rules (
            id UUID PRIMARY KEY,
            name VARCHAR NOT NULL,
            event_source VARCHAR NOT NULL,
            event_type VARCHAR NOT NULL,
            target_match VARCHAR,
            action VARCHAR NOT NULL DEFAULT 'queue_scan',
            tool VARCHAR NOT NULL DEFAULT 'openvas',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            metadata_json JSON NOT NULL DEFAULT '{}'::json,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS monitoring_events (
            id UUID PRIMARY KEY,
            source VARCHAR NOT NULL,
            event_type VARCHAR NOT NULL,
            target VARCHAR NOT NULL,
            severity VARCHAR NOT NULL DEFAULT 'medium',
            status VARCHAR NOT NULL DEFAULT 'received',
            payload JSON NOT NULL DEFAULT '{}'::json,
            triggered_scan_id UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS security_incidents (
            id UUID PRIMARY KEY,
            title VARCHAR NOT NULL,
            source VARCHAR NOT NULL,
            severity VARCHAR NOT NULL DEFAULT 'medium',
            status VARCHAR NOT NULL DEFAULT 'open',
            target VARCHAR NOT NULL,
            summary TEXT,
            related_finding_ids JSON NOT NULL DEFAULT '[]'::json,
            metadata_json JSON NOT NULL DEFAULT '{}'::json,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS compliance_templates (
            id UUID PRIMARY KEY,
            name VARCHAR NOT NULL UNIQUE,
            framework VARCHAR NOT NULL,
            controls JSON NOT NULL DEFAULT '[]'::json,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS compliance_assessments (
            id UUID PRIMARY KEY,
            template_id UUID NOT NULL REFERENCES compliance_templates(id),
            name VARCHAR NOT NULL,
            status VARCHAR NOT NULL DEFAULT 'draft',
            score VARCHAR NOT NULL DEFAULT '0',
            summary JSON NOT NULL DEFAULT '{}'::json,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ai_analysis_cache (
            id UUID PRIMARY KEY,
            cache_key VARCHAR NOT NULL UNIQUE,
            analysis_type VARCHAR NOT NULL,
            provider VARCHAR NOT NULL DEFAULT 'local-fallback',
            model VARCHAR NOT NULL DEFAULT 'operator-playbook',
            input_fingerprint VARCHAR NOT NULL,
            request_payload JSON NOT NULL DEFAULT '{}'::json,
            response_payload JSON NOT NULL DEFAULT '{}'::json,
            hit_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ai_decision_logs (
            id UUID PRIMARY KEY,
            analysis_type VARCHAR NOT NULL,
            actor VARCHAR NOT NULL,
            provider VARCHAR NOT NULL DEFAULT 'local-fallback',
            model VARCHAR NOT NULL DEFAULT 'operator-playbook',
            cache_key VARCHAR,
            input_fingerprint VARCHAR NOT NULL,
            request_payload JSON NOT NULL DEFAULT '{}'::json,
            response_payload JSON NOT NULL DEFAULT '{}'::json,
            decision_reason TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_ai_analysis_cache_cache_key ON ai_analysis_cache (cache_key)",
        "CREATE INDEX IF NOT EXISTS ix_ai_analysis_cache_analysis_type ON ai_analysis_cache (analysis_type)",
        "CREATE INDEX IF NOT EXISTS ix_ai_decision_logs_analysis_type ON ai_decision_logs (analysis_type)",
        "CREATE INDEX IF NOT EXISTS ix_ai_decision_logs_actor ON ai_decision_logs (actor)",
        """
        CREATE TABLE IF NOT EXISTS endpoint_software_inventory (
            id UUID PRIMARY KEY,
            endpoint_name VARCHAR NOT NULL,
            hostname VARCHAR,
            ip_address VARCHAR,
            os_name VARCHAR,
            source VARCHAR NOT NULL DEFAULT 'agent',
            reported_by VARCHAR,
            installed_apps JSON NOT NULL DEFAULT '[]'::json,
            approved_baseline JSON NOT NULL DEFAULT '[]'::json,
            detected_apps JSON NOT NULL DEFAULT '[]'::json,
            status VARCHAR NOT NULL DEFAULT 'received',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_endpoint_software_inventory_endpoint_name ON endpoint_software_inventory (endpoint_name)",
        "CREATE INDEX IF NOT EXISTS ix_endpoint_software_inventory_hostname ON endpoint_software_inventory (hostname)",
        "CREATE INDEX IF NOT EXISTS ix_endpoint_software_inventory_ip_address ON endpoint_software_inventory (ip_address)",
        """
        CREATE TABLE IF NOT EXISTS software (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            vendor VARCHAR,
            version VARCHAR,
            category VARCHAR NOT NULL DEFAULT 'OS',
            cpe VARCHAR,
            status VARCHAR NOT NULL DEFAULT 'UNAUTHORIZED',
            risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            cves JSON NOT NULL DEFAULT '[]'::json,
            discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_software_name ON software (name)",
        """
        CREATE TABLE IF NOT EXISTS software_assets (
            id SERIAL PRIMARY KEY,
            software_id INT NOT NULL REFERENCES software(id) ON DELETE CASCADE,
            asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
            ip_address VARCHAR,
            hostname VARCHAR,
            endpoint_name VARCHAR,
            source VARCHAR NOT NULL DEFAULT 'Nmap -sV',
            installed_path VARCHAR,
            discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "ALTER TABLE software_assets ADD COLUMN IF NOT EXISTS ip_address VARCHAR",
        "ALTER TABLE software_assets ADD COLUMN IF NOT EXISTS hostname VARCHAR",
        "ALTER TABLE software_assets ADD COLUMN IF NOT EXISTS endpoint_name VARCHAR",
        "ALTER TABLE software_assets ADD COLUMN IF NOT EXISTS source VARCHAR DEFAULT 'Nmap -sV'",
        "CREATE INDEX IF NOT EXISTS ix_software_assets_ip_address ON software_assets (ip_address)",
        """
        CREATE TABLE IF NOT EXISTS whitelist_software (
            id SERIAL PRIMARY KEY,
            name VARCHAR UNIQUE NOT NULL,
            vendor VARCHAR,
            reason VARCHAR,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_whitelist_software_name ON whitelist_software (name)",
        "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_title ON vulnerabilities (title)",
        "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_severity ON vulnerabilities (severity)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
