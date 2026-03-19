const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");

const usePostgres = Boolean(process.env.DATABASE_URL);
let db = null;

/** Lazy Pool: resolve DB host to IPv4 before connect (Render etc. have no route to IPv6). */
let postgresPoolPromise = null;

async function resolveFirstIPv4(hostname) {
  const dns = require("dns").promises;
  try {
    const records = await dns.resolve4(hostname);
    if (records.length) {
      return records[0];
    }
  } catch (_) {
    /* no A records */
  }
  try {
    const results = await dns.lookup(hostname, { all: true });
    const v4 = results.find((entry) => entry.family === 4);
    if (v4) {
      return v4.address;
    }
  } catch (_) {
    /* ignore */
  }
  return null;
}

async function createPostgresPool() {
  const { parse } = require("pg-connection-string");
  const { Pool } = require("pg");
  const parsed = parse(process.env.DATABASE_URL);
  let hostname = parsed.host;
  if (!hostname) {
    throw new Error("DATABASE_URL is missing a host. Check the connection string.");
  }
  hostname = hostname.trim();
  if (/\s/.test(hostname)) {
    throw new Error(
      `Postgres host contains a space or invalid character: "${hostname}". ` +
        `Often this is a typo: use "us-east-1" (hyphens), not "us-east 1". Re-copy Session pooler URL from Supabase.`
    );
  }

  let host = hostname;
  const allowIpv6Fallback = process.env.PG_ALLOW_IPV6 === "true";
  const skipIpv4Resolve = process.env.PG_RESOLVE_IPV4 === "false";

  if (!skipIpv4Resolve) {
    const ipv4 = await resolveFirstIPv4(hostname);
    if (ipv4) {
      host = ipv4;
    } else if (!allowIpv6Fallback) {
      const isSupabaseDirect =
        /^db\.[a-z0-9]+\.supabase\.co$/i.test(hostname) || hostname.endsWith(".supabase.co");
      const hint = isSupabaseDirect
        ? [
            "",
            "Supabase direct hostnames (db.*.supabase.co) are IPv6-only by default.",
            "On Render you need the Session pooler URL (IPv4):",
            "Supabase Dashboard → Connect → Connection string → Session pooler, port 5432.",
            "It looks like: postgresql://postgres.[PROJECT_REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres",
            "Or add Supabase’s paid IPv4 add-on for the direct host.",
          ].join("\n")
        : "\nNo IPv4 (A record) found for this host. Use a host with IPv4 or set PG_ALLOW_IPV6=true if your network supports IPv6.";

      throw new Error(`Postgres: no IPv4 address for host "${hostname}".${hint}`);
    }
  }

  const useSsl = process.env.PGSSL !== "false";
  const ssl = useSsl
    ? {
        rejectUnauthorized: false,
        // TLS cert is for the hostname, not the bare IP
        servername: hostname,
      }
    : false;
  return new Pool({
    host,
    port: parsed.port || 5432,
    user: parsed.user,
    password: parsed.password,
    database: parsed.database,
    ssl,
  });
}

async function getPostgresPool() {
  if (!postgresPoolPromise) {
    postgresPoolPromise = createPostgresPool();
  }
  return postgresPoolPromise;
}

async function pgQuery(text, params) {
  const pool = await getPostgresPool();
  return pool.query(text, params);
}

if (!usePostgres) {
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
  const result = await pgQuery(translatedSql, params);
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
  const result = await pgQuery(translateForPostgres(sql), params);
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
  const result = await pgQuery(translateForPostgres(sql), params);
  return result.rows;
}

async function initializeDatabase() {
  if (usePostgres) {
    await pgQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'lead_analyst', 'analyst', 'lead_internal_affairs', 'internal_affairs'))
      );
    `);
    await pgQuery(`
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
    await pgQuery(`
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
    await pgQuery(`
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
    await pgQuery(`
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
    await pgQuery(`
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
    await pgQuery(`
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
