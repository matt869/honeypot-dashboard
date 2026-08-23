-- 003_campaign_indexes.sql
--
-- Composites for the campaign list. Single-column indexes come from SQLAlchemy
-- metadata (storage/models.py); this adds the pair the dashboard sorts on.
--
-- Every statement is IF NOT EXISTS so the file is safe to replay.

-- Campaigns are always read for one threshold, ordered by how big they are.
CREATE INDEX IF NOT EXISTS ix_campaigns_threshold_size
    ON campaigns (threshold, size);
