CREATE TABLE IF NOT EXISTS reports (
    id           SERIAL PRIMARY KEY,
    host         TEXT,
    time         TIMESTAMP,
    modules      TEXT,
    dmesg        TEXT,
    full_report  JSONB
);

CREATE TABLE IF NOT EXISTS baseline_modules (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    module_name TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    is_approved BOOLEAN DEFAULT FALSE,
    approved_by TEXT,
    approved_at TIMESTAMP,
    UNIQUE(host, module_name)
);

CREATE TABLE IF NOT EXISTS baseline_kernel_params (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    param_name TEXT NOT NULL,
    param_value TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL,
    UNIQUE(host, param_name)
);

CREATE INDEX IF NOT EXISTS idx_baseline_modules_host ON baseline_modules(host);
CREATE INDEX IF NOT EXISTS idx_baseline_kernel_params_host ON baseline_kernel_params(host);

CREATE TABLE IF NOT EXISTS kernel_param_changes (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    param_name TEXT NOT NULL,
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS module_changes (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    module_name TEXT NOT NULL,
    action TEXT NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_host ON reports(host);
CREATE INDEX IF NOT EXISTS idx_reports_time ON reports(time);
CREATE INDEX IF NOT EXISTS idx_reports_full_report ON reports USING gin(full_report); 