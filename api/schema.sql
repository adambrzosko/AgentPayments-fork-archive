-- AgentPayments Platform API — Postgres schema
-- Run once against a fresh database:
--   psql $DATABASE_URL -f schema.sql

CREATE TABLE IF NOT EXISTS vendors (
  vendor_id              VARCHAR(8)   PRIMARY KEY,
  email                  VARCHAR(255) UNIQUE NOT NULL,
  name                   VARCHAR(255) NOT NULL,
  api_key                VARCHAR(255) UNIQUE NOT NULL,
  verification_secret    VARCHAR(64)  NOT NULL,
  plan                   VARCHAR(50)  NOT NULL DEFAULT 'free',
  keys_issued            INTEGER      NOT NULL DEFAULT 0,
  -- Email verification
  email_verified         BOOLEAN      NOT NULL DEFAULT FALSE,
  verification_token     VARCHAR(64),
  -- Stripe
  stripe_customer_id         VARCHAR(255),
  stripe_subscription_item_id VARCHAR(255),
  -- Metadata
  created_at             BIGINT       NOT NULL
);

-- Daily usage log for dashboard charts and metered billing reconciliation.
CREATE TABLE IF NOT EXISTS usage_daily (
  id          SERIAL       PRIMARY KEY,
  vendor_id   VARCHAR(8)   NOT NULL REFERENCES vendors(vendor_id) ON DELETE CASCADE,
  event_type  VARCHAR(50)  NOT NULL,   -- 'key_issued'
  day         DATE         NOT NULL DEFAULT CURRENT_DATE,
  count       INTEGER      NOT NULL DEFAULT 1
);

-- One row per vendor per day per event_type (upserted on each event).
CREATE UNIQUE INDEX IF NOT EXISTS idx_usage_daily_unique
  ON usage_daily (vendor_id, event_type, day);

CREATE INDEX IF NOT EXISTS idx_usage_daily_vendor
  ON usage_daily (vendor_id, day DESC);
