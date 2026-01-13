-- Database Schema for NapScan Vulnerability Scanning System
-- PostgreSQL

-- ============================================
-- BATCHES TABLE
-- Represents a batch scan (one user request)
-- ============================================
CREATE TABLE batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    target VARCHAR(500) NOT NULL,
    expected_job_count INT NOT NULL DEFAULT 0,
    completed_job_count INT NOT NULL DEFAULT 0,
    failed_job_count INT NOT NULL DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed, canceled
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    
    INDEX idx_user_batches (user_id, created_at DESC),
    INDEX idx_batch_status (status, created_at DESC),
    INDEX idx_batch_id (batch_id)
);

-- ============================================
-- SCAN_JOBS TABLE
-- Individual scanner executions within a batch
-- ============================================
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    tool_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, success, failed, canceled
    target VARCHAR(500) NOT NULL,
    config JSONB, -- Scanner-specific configuration
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_ms BIGINT, -- Duration in milliseconds
    raw_result JSONB, -- Raw scanner output
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_batch_jobs (batch_id, created_at),
    INDEX idx_job_status (status, created_at),
    INDEX idx_tool_name (tool_name, created_at DESC)
);

-- ============================================
-- VULNERABILITIES TABLE
-- Normalized vulnerability findings
-- ============================================
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    scan_job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
    
    -- Core vulnerability data
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- info, low, medium, high, critical
    description TEXT,
    
    -- Asset information
    affected_asset JSONB NOT NULL, -- Array of affected assets
    
    -- Source information
    source_tool VARCHAR(100) NOT NULL,
    
    -- Evidence and remediation
    evidence TEXT,
    remediation TEXT,
    
    -- Vulnerability identifiers
    cve VARCHAR(50),
    cwe VARCHAR(50),
    cvss DECIMAL(3,1),
    
    -- Additional metadata
    metadata JSONB,
    
    -- Deduplication
    fingerprint VARCHAR(64), -- Hash for deduplication
    is_duplicate BOOLEAN DEFAULT FALSE,
    duplicate_of UUID REFERENCES vulnerabilities(id),
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_batch_vulnerabilities (batch_id, severity),
    INDEX idx_vulnerability_severity (severity, created_at DESC),
    INDEX idx_vulnerability_source (source_tool, created_at DESC),
    INDEX idx_vulnerability_cve (cve),
    INDEX idx_vulnerability_fingerprint (fingerprint),
    INDEX idx_duplicate_vulns (is_duplicate, duplicate_of)
);

-- ============================================
-- BATCH_REPORTS TABLE
-- Aggregated analysis reports
-- ============================================
CREATE TABLE batch_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID UNIQUE NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    
    -- Summary statistics
    total_vulnerabilities INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    info_count INT NOT NULL DEFAULT 0,
    
    -- Risk scoring
    overall_risk_score DECIMAL(5,2),
    risk_level VARCHAR(20), -- low, medium, high, critical
    
    -- Tool coverage
    tools_executed JSONB, -- Array of tools that ran successfully
    tools_failed JSONB, -- Array of tools that failed
    
    -- Complete report
    report_data JSONB NOT NULL, -- Full structured report
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_report_batch (batch_id)
);

-- ============================================
-- SCAN_METADATA TABLE
-- Additional scan context and metadata
-- ============================================
CREATE TABLE scan_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    
    -- Scan context
    scan_type VARCHAR(50), -- full, single, custom
    requested_tools JSONB, -- Array of requested scanner names
    
    -- Network/target information
    target_info JSONB, -- IP ranges, domains, URLs, etc.
    
    -- User preferences
    user_preferences JSONB,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_metadata_batch (batch_id)
);

-- ============================================
-- AUDIT_LOG TABLE
-- Audit trail for compliance
-- ============================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    batch_id UUID REFERENCES batches(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- create_batch, start_scan, complete_scan, etc.
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_audit_user (user_id, created_at DESC),
    INDEX idx_audit_batch (batch_id, created_at DESC),
    INDEX idx_audit_action (action, created_at DESC)
);

-- ============================================
-- TRIGGERS
-- ============================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_batches_updated_at BEFORE UPDATE ON batches
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scan_jobs_updated_at BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Auto-update batch completed_job_count
CREATE OR REPLACE FUNCTION update_batch_job_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'success' OR NEW.status = 'failed' THEN
        UPDATE batches 
        SET 
            completed_job_count = (
                SELECT COUNT(*) FROM scan_jobs 
                WHERE batch_id = NEW.batch_id 
                AND status IN ('success', 'failed')
            ),
            failed_job_count = (
                SELECT COUNT(*) FROM scan_jobs 
                WHERE batch_id = NEW.batch_id 
                AND status = 'failed'
            ),
            updated_at = NOW()
        WHERE id = NEW.batch_id;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_batch_counts AFTER UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_batch_job_counts();

-- ============================================
-- VIEWS
-- ============================================

-- View for batch summary with job statistics
CREATE VIEW v_batch_summary AS
SELECT 
    b.id,
    b.batch_id,
    b.user_id,
    b.target,
    b.status,
    b.expected_job_count,
    b.completed_job_count,
    b.failed_job_count,
    b.created_at,
    b.completed_at,
    COALESCE(r.total_vulnerabilities, 0) as total_vulnerabilities,
    COALESCE(r.critical_count, 0) as critical_count,
    COALESCE(r.high_count, 0) as high_count,
    COALESCE(r.medium_count, 0) as medium_count,
    COALESCE(r.low_count, 0) as low_count,
    COALESCE(r.info_count, 0) as info_count,
    r.overall_risk_score,
    r.risk_level
FROM batches b
LEFT JOIN batch_reports r ON b.id = r.batch_id;

-- View for vulnerability statistics by tool
CREATE VIEW v_vulnerability_by_tool AS
SELECT 
    source_tool,
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT batch_id) as batches_affected
FROM vulnerabilities
WHERE is_duplicate = FALSE
GROUP BY source_tool, severity;

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

-- Composite index for common queries
CREATE INDEX idx_batches_user_status ON batches(user_id, status, created_at DESC);
CREATE INDEX idx_vulnerabilities_batch_severity ON vulnerabilities(batch_id, severity, is_duplicate);
CREATE INDEX idx_scan_jobs_batch_status ON scan_jobs(batch_id, status);

-- ============================================
-- SAMPLE QUERIES
-- ============================================

/*
-- Get all batches for a user with summary
SELECT * FROM v_batch_summary 
WHERE user_id = 'user123' 
ORDER BY created_at DESC 
LIMIT 10;

-- Get all vulnerabilities for a batch
SELECT * FROM vulnerabilities 
WHERE batch_id = 'batch-uuid' 
AND is_duplicate = FALSE
ORDER BY 
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        WHEN 'info' THEN 5
    END;

-- Get batch with all jobs and vulnerabilities
SELECT 
    b.*,
    json_agg(DISTINCT sj.*) as scan_jobs,
    json_agg(DISTINCT v.*) FILTER (WHERE v.id IS NOT NULL) as vulnerabilities
FROM batches b
LEFT JOIN scan_jobs sj ON b.id = sj.batch_id
LEFT JOIN vulnerabilities v ON b.id = v.batch_id AND v.is_duplicate = FALSE
WHERE b.batch_id = 'batch-id'
GROUP BY b.id;
*/
