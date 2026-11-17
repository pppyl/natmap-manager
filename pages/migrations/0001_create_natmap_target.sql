CREATE TABLE natmap_target (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  location TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
