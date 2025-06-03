-- Таблица для хранения базового состояния модулей
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

-- Таблица для хранения базового состояния параметров ядра
CREATE TABLE IF NOT EXISTS baseline_kernel_params (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    param_name TEXT NOT NULL,
    param_value TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL, -- sys_kernel, sys_security, runtime_params
    UNIQUE(host, param_name)
);

-- Индексы для быстрого поиска
CREATE INDEX idx_baseline_modules_host ON baseline_modules(host);
CREATE INDEX idx_baseline_kernel_params_host ON baseline_kernel_params(host);

-- Таблица для хранения истории изменений параметров
CREATE TABLE IF NOT EXISTS kernel_param_changes (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    param_name TEXT NOT NULL,
    old_value TEXT NOT NULL,
    new_value TEXT NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    category TEXT NOT NULL
);

-- Таблица для хранения истории изменений модулей
CREATE TABLE IF NOT EXISTS module_changes (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    module_name TEXT NOT NULL,
    action TEXT NOT NULL, -- 'added' или 'removed'
    changed_at TIMESTAMP NOT NULL DEFAULT NOW()
); 