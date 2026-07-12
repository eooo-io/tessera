-- 0014_guardian_lock_generation: durable cross-process explicit-lock signal.

CREATE TABLE guardian_lock_state (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    updated_at TEXT NOT NULL
);

INSERT INTO guardian_lock_state (singleton, generation, updated_at)
VALUES (1, 0, datetime('now'));
