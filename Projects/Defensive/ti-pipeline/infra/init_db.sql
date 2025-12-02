-- Threat Intelligence Pipeline Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- IOCs table
CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    type VARCHAR(20) NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email')),
    source VARCHAR(255) NOT NULL,
    confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    tags TEXT[] DEFAULT '{}',
    description TEXT,
    analyst_verdict VARCHAR(50) CHECK (analyst_verdict IN ('malicious', 'suspicious', 'benign', 'false_positive')),
    analyst_confidence INTEGER CHECK (analyst_confidence >= 0 AND analyst_confidence <= 100),
    analyst_notes TEXT,
    analyst_updated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enrichment records
CREATE TABLE enrichment_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_id UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source VARCHAR(100) NOT NULL,
    data JSONB NOT NULL,
    normalized_data JSONB,
    confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ttl_hours INTEGER DEFAULT 24,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Feed tracking
CREATE TABLE feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    version VARCHAR(100),
    description TEXT,
    last_ingestion TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log for enrichment calls
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(100) NOT NULL,
    provider VARCHAR(100),
    request_hash VARCHAR(64),
    response_hash VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX idx_iocs_normalized_value ON iocs(normalized_value);
CREATE INDEX idx_iocs_type ON iocs(type);
CREATE INDEX idx_iocs_source ON iocs(source);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen DESC);
CREATE INDEX idx_enrichment_ioc_id ON enrichment_records(ioc_id);
CREATE INDEX idx_enrichment_source ON enrichment_records(source);
CREATE INDEX idx_enrichment_timestamp ON enrichment_records(timestamp DESC);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);

-- Update trigger for iocs
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_iocs_updated_at BEFORE UPDATE ON iocs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
