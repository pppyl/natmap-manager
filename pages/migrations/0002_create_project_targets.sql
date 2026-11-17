CREATE TABLE natmap_projects (
  project TEXT PRIMARY KEY NOT NULL,
  location TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

INSERT INTO natmap_projects (project, location, expires_at)
SELECT '', location, expires_at FROM natmap_target WHERE id = 1;
