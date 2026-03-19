const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const usePostgres = Boolean(process.env.DATABASE_URL);
let db = null;
let pool = null;

if (usePostgres) {
  // Supabase often resolves to IPv6 first; some hosts (e.g. Render) have no working IPv6
  // route → connect ENETUNREACH. Prefer A (IPv4) records for postgres hostname.
  if (process.env.PG_DNS_IPV4_FIRST !== "false") {
    try {
      require("dns").setDefaultResultOrder("ipv4first");
    } catch (_) {
      /* Node < 17: ignore */
    }
  }
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
  });
} else {
  const sqlite3 = require("sqlite3").verbose();
  const dataDir = path.join(__dirname, "data");
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  const dbPath = path.join(dataDir, "intelligence.db");
  db = new sqlite3.Database(dbPath);
}

function translateForPostgres(sql) {
  const withNow = sql.replaceAll("datetime('now')", "NOW()");
  let index = 0;
  return withNow.replace(/\?/g, () => {
    index += 1;
    return `$${index}`;
  });
}

async function run(sql, params = []) {
  if (!usePostgres) {
    return new Promise((resolve, reject) => {
      db.run(sql, params, function onRun(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve(this);
      });
    });
  }

  let translatedSql = translateForPostgres(sql).trim();
  const isInsert = /^insert\s+/i.test(translatedSql);
  if (isInsert && !/returning\s+/i.test(translatedSql)) {
    translatedSql = `${translatedSql} RETURNING id`;
  }
  const result = await pool.query(translatedSql, params);
  return { lastID: result.rows?.[0]?.id || null, rowCount: result.rowCount };
}

async function get(sql, params = []) {
  if (!usePostgres) {
    return new Promise((resolve, reject) => {
      db.get(sql, params, (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(row);
      });
    });
  }
  const result = await pool.query(translateForPostgres(sql), params);
  return result.rows[0];
}

async function all(sql, params = []) {
  if (!usePostgres) {
    return new Promise((resolve, reject) => {
      db.all(sql, params, (err, rows) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(rows);
      });
    });
  }
  const result = await pool.query(translateForPostgres(sql), params);
  return result.rows;
}

async function initializeDatabase() {
  if (usePostgres) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'lead_analyst', 'analyst', 'lead_internal_affairs', 'internal_affairs'))
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dossiers (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        faction TEXT NOT NULL,
        affiliation TEXT NOT NULL,
        created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_by_username TEXT NOT NULL DEFAULT '',
        assigned_investigator_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        assigned_investigator TEXT NOT NULL DEFAULT '',
        previous_warrants TEXT NOT NULL,
        risk_level TEXT NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
        notes TEXT NOT NULL DEFAULT '',
        image_path TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        dossier_id INTEGER NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
        analyst_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        analyst_name TEXT NOT NULL,
        subject_name TEXT NOT NULL,
        subject_faction TEXT NOT NULL,
        subject_affiliation TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS report_incidents (
        id SERIAL PRIMARY KEY,
        report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        incident_order INTEGER NOT NULL,
        incident_title TEXT NOT NULL,
        incident_datetime TEXT NOT NULL,
        incident_description TEXT NOT NULL,
        incident_outcome TEXT NOT NULL
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ia_dossiers (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        faction TEXT NOT NULL,
        affiliation TEXT NOT NULL,
        created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_by_username TEXT NOT NULL DEFAULT '',
        assigned_investigator_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        assigned_investigator TEXT NOT NULL DEFAULT '',
        previous_warrants TEXT NOT NULL,
        risk_level TEXT NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
        notes TEXT NOT NULL DEFAULT '',
        image_path TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ia_reports (
        id SERIAL PRIMARY KEY,
        dossier_id INTEGER NOT NULL REFERENCES ia_dossiers(id) ON DELETE CASCADE,
        analyst_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        analyst_name TEXT NOT NULL,
        subject_name TEXT NOT NULL,
        subject_faction TEXT NOT NULL,
        subject_affiliation TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ia_report_incidents (
        id SERIAL PRIMARY KEY,
        report_id INTEGER NOT NULL REFERENCES ia_reports(id) ON DELETE CASCADE,
        incident_order INTEGER NOT NULL,
        incident_title TEXT NOT NULL,
        incident_datetime TEXT NOT NULL,
        incident_description TEXT NOT NULL,
        incident_outcome TEXT NOT NULL
      );
    `);
  } else {
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'lead_analyst', 'analyst', 'lead_internal_affairs', 'internal_affairs'))
      )
    `);

  await run(`
    CREATE TABLE IF NOT EXISTS dossiers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      faction TEXT NOT NULL,
      affiliation TEXT NOT NULL,
      created_by_user_id INTEGER,
      created_by_username TEXT NOT NULL DEFAULT '',
      assigned_investigator_user_id INTEGER,
      assigned_investigator TEXT NOT NULL DEFAULT '',
      previous_warrants TEXT NOT NULL,
      risk_level TEXT NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
      notes TEXT NOT NULL DEFAULT '',
      image_path TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (created_by_user_id) REFERENCES users(id),
      FOREIGN KEY (assigned_investigator_user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dossier_id INTEGER NOT NULL,
      analyst_user_id INTEGER NOT NULL,
      analyst_name TEXT NOT NULL,
      subject_name TEXT NOT NULL,
      subject_faction TEXT NOT NULL,
      subject_affiliation TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (dossier_id) REFERENCES dossiers(id),
      FOREIGN KEY (analyst_user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS report_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      incident_order INTEGER NOT NULL,
      incident_title TEXT NOT NULL,
      incident_datetime TEXT NOT NULL,
      incident_description TEXT NOT NULL,
      incident_outcome TEXT NOT NULL,
      FOREIGN KEY (report_id) REFERENCES reports(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS ia_dossiers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      faction TEXT NOT NULL,
      affiliation TEXT NOT NULL,
      created_by_user_id INTEGER,
      created_by_username TEXT NOT NULL DEFAULT '',
      assigned_investigator_user_id INTEGER,
      assigned_investigator TEXT NOT NULL DEFAULT '',
      previous_warrants TEXT NOT NULL,
      risk_level TEXT NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High')),
      notes TEXT NOT NULL DEFAULT '',
      image_path TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (created_by_user_id) REFERENCES users(id),
      FOREIGN KEY (assigned_investigator_user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS ia_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      dossier_id INTEGER NOT NULL,
      analyst_user_id INTEGER NOT NULL,
      analyst_name TEXT NOT NULL,
      subject_name TEXT NOT NULL,
      subject_faction TEXT NOT NULL,
      subject_affiliation TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (dossier_id) REFERENCES ia_dossiers(id),
      FOREIGN KEY (analyst_user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS ia_report_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id INTEGER NOT NULL,
      incident_order INTEGER NOT NULL,
      incident_title TEXT NOT NULL,
      incident_datetime TEXT NOT NULL,
      incident_description TEXT NOT NULL,
      incident_outcome TEXT NOT NULL,
      FOREIGN KEY (report_id) REFERENCES ia_reports(id)
    )
  `);

    const usersCreate = await get("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'");
    const usersSql = usersCreate?.sql || "";
    if (!usersSql.includes("'lead_internal_affairs'") || !usersSql.includes("'internal_affairs'")) {
    await run("ALTER TABLE users RENAME TO users_old");
    await run(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'lead_analyst', 'analyst', 'lead_internal_affairs', 'internal_affairs'))
      )
    `);
    await run(`
      INSERT INTO users (id, username, password_hash, role)
      SELECT id, username, password_hash,
        CASE
          WHEN role IN ('admin', 'lead_analyst', 'analyst', 'lead_internal_affairs', 'internal_affairs') THEN role
          ELSE 'analyst'
        END
      FROM users_old
    `);
    await run("DROP TABLE users_old");
  }

    const userColumns = await all("PRAGMA table_info(users)");
    const hasRoleColumn = userColumns.some((column) => column.name === "role");
    if (!hasRoleColumn) {
      await run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'");
    }

    const dossierColumns = await all("PRAGMA table_info(dossiers)");
    const hasCreatedByUserId = dossierColumns.some((column) => column.name === "created_by_user_id");
    if (!hasCreatedByUserId) {
      await run("ALTER TABLE dossiers ADD COLUMN created_by_user_id INTEGER");
    }

    const hasCreatedByUsername = dossierColumns.some((column) => column.name === "created_by_username");
    if (!hasCreatedByUsername) {
      await run("ALTER TABLE dossiers ADD COLUMN created_by_username TEXT NOT NULL DEFAULT ''");
    }

    const hasAssignedInvestigatorUserId = dossierColumns.some((column) => column.name === "assigned_investigator_user_id");
    if (!hasAssignedInvestigatorUserId) {
      await run("ALTER TABLE dossiers ADD COLUMN assigned_investigator_user_id INTEGER");
    }

    const hasAssignedInvestigator = dossierColumns.some((column) => column.name === "assigned_investigator");
    if (!hasAssignedInvestigator) {
      await run("ALTER TABLE dossiers ADD COLUMN assigned_investigator TEXT NOT NULL DEFAULT ''");
    }
  }

  const adminUsername = process.env.ADMIN_USERNAME || "admin";
  const adminPassword = process.env.ADMIN_PASSWORD || "change-this-password";
  const existingAdmin = await get("SELECT id FROM users WHERE username = ?", [adminUsername]);
  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", [adminUsername, passwordHash]);
  } else {
    await run("UPDATE users SET role = 'admin' WHERE username = ?", [adminUsername]);
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  initializeDatabase,
};
