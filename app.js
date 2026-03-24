const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");

const { get, all, run, initializeDatabase } = require("./db");
const { requireAuth, requireAdmin } = require("./middleware/auth");
const {
  WARRANT_CRIMES,
  WARRANT_DURATION_OPTIONS,
  WARRANT_CLASSIFICATIONS,
  WARRANT_DURATION_MS,
  crimeLabel,
  classificationLabel,
  computeExpiryIso,
} = require("./warrant-config");

dotenv.config();

const app = express();
const port = Number(process.env.PORT) || 3000;

const factions = [
  "Law enforcement Department",
  "Freedom Defense Corp",
  "Brotherhood of Shadows",
  "Mercenaries of the Blood",
  "Vortex Incorporated",
  "Eurocorp",
  "Colonial Mining Guild",
  "Guardians of Mankind",
];

const riskLevels = ["Low", "Medium", "High"];

/** Analysts and lead analysts may be assigned to normal dossiers. */
function getAssignableDossierInvestigators() {
  return all(
    "SELECT id, username, role FROM users WHERE role IN ('analyst', 'lead_analyst') ORDER BY username ASC"
  );
}

/** Only IA roles may be assigned to IA dossiers. */
function getAssignableIaAgents() {
  return all(
    "SELECT id, username, role FROM users WHERE role IN ('internal_affairs', 'lead_internal_affairs') ORDER BY username ASC"
  );
}

function canEditWarrant(role) {
  return ["admin", "analyst", "lead_analyst", "internal_affairs", "lead_internal_affairs"].includes(role);
}

function canAssignMainDossier(role) {
  return ["admin", "lead_analyst", "lead_internal_affairs"].includes(role);
}

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const hasCloudinaryConfig =
  Boolean(process.env.CLOUDINARY_CLOUD_NAME) &&
  Boolean(process.env.CLOUDINARY_API_KEY) &&
  Boolean(process.env.CLOUDINARY_API_SECRET);

if (hasCloudinaryConfig) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
}

const storage = hasCloudinaryConfig
  ? new CloudinaryStorage({
      cloudinary,
      params: {
        folder: "gd-intelligence",
        allowed_formats: ["jpg", "jpeg", "png", "webp"],
      },
    })
  : multer.diskStorage({
      destination: (req, file, cb) => cb(null, uploadDir),
      filename: (req, file, cb) => {
        const ext = path.extname(file.originalname || "").toLowerCase();
        const safeExt = [".jpg", ".jpeg", ".png", ".webp"].includes(ext) ? ext : ".png";
        cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExt}`);
      },
    });

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(uploadDir));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace-me-with-a-real-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.session?.user || null;
  res.locals.isAdmin = req.session?.user?.role === "admin";
  res.locals.isLeadOrAdmin = ["admin", "lead_analyst", "lead_internal_affairs"].includes(req.session?.user?.role);
  res.locals.canAccessIa = ["admin", "lead_internal_affairs", "internal_affairs"].includes(req.session?.user?.role);
  res.locals.factions = factions;
  res.locals.riskLevels = riskLevels;
  res.locals.warrantCrimes = WARRANT_CRIMES;
  res.locals.warrantDurationOptions = WARRANT_DURATION_OPTIONS;
  res.locals.warrantClassifications = WARRANT_CLASSIFICATIONS;
  res.locals.crimeLabel = crimeLabel;
  res.locals.classificationLabel = classificationLabel;
  next();
});

function requireIaAccess(req, res, next) {
  if (!req.session?.user) {
    res.redirect("/login");
    return;
  }
  if (!["admin", "lead_internal_affairs", "internal_affairs"].includes(req.session.user.role)) {
    res.status(403).send("Forbidden");
    return;
  }
  next();
}

function canAssignIa(req) {
  return ["admin", "lead_internal_affairs"].includes(req.session?.user?.role);
}

app.get("/active-warrants", async (req, res, next) => {
  try {
    const rows = await all(
      `SELECT id, name, warrant_crime, warrant_classification, warrant_description, warrant_expires_at
       FROM dossiers
       WHERE warrant_status = 'active'
         AND warrant_expires_at IS NOT NULL
         AND warrant_expires_at > datetime('now')
         AND warrant_classification IN ('AoS', 'EoS', 'KoS')
       ORDER BY warrant_expires_at ASC`
    );
    const warrants = rows.map((r) => ({
      ...r,
      crimeLabelText: crimeLabel(r.warrant_crime),
      classificationShort: r.warrant_classification || "—",
      expiresDisplay: r.warrant_expires_at
        ? new Date(r.warrant_expires_at).toLocaleString(undefined, {
            dateStyle: "medium",
            timeStyle: "short",
          })
        : "",
    }));
    res.render("active-warrants", { warrants });
  } catch (error) {
    next(error);
  }
});

app.get("/", requireAuth, async (req, res, next) => {
  try {
    const name = (req.query.name || "").trim();
    const faction = (req.query.faction || "").trim();
    const risk = (req.query.risk || "").trim();

    const where = [];
    const params = [];

    if (name) {
      where.push("d.name LIKE ?");
      params.push(`%${name}%`);
    }
    if (faction) {
      where.push("d.faction = ?");
      params.push(faction);
    }
    if (risk) {
      where.push("d.risk_level = ?");
      params.push(risk);
    }

    const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const dossiers = await all(
      `SELECT d.id, d.name, d.faction, d.affiliation, d.created_by_username, d.assigned_investigator, d.warrant_status, d.warrant_crime, d.warrant_classification, d.warrant_description, d.warrant_expires_at, d.risk_level, d.notes, d.image_path, d.created_at, d.updated_at,
              COUNT(r.id) AS report_count
       FROM dossiers d
       LEFT JOIN reports r ON r.dossier_id = d.id
       ${whereClause}
       GROUP BY d.id
       ORDER BY d.updated_at DESC`,
      params
    );

    res.render("index", {
      dossiers,
      filters: { name, faction, risk },
    });
  } catch (error) {
    next(error);
  }
});

app.get("/reports/my", requireAuth, async (req, res, next) => {
  try {
    const reports = await all(
      `SELECT r.id, r.analyst_name, r.subject_name, r.subject_faction, r.subject_affiliation, r.created_at, r.updated_at,
              r.dossier_id, COUNT(ri.id) AS incident_count
       FROM reports r
       LEFT JOIN report_incidents ri ON ri.report_id = r.id
       WHERE r.analyst_user_id = ?
       GROUP BY r.id
       ORDER BY r.updated_at DESC`,
      [req.session.user.id]
    );
    res.render("my-reports", { reports });
  } catch (error) {
    next(error);
  }
});

app.get("/assignments/my", requireAuth, async (req, res, next) => {
  try {
    const dossiers = await all(
      `SELECT d.id, d.name, d.faction, d.affiliation, d.created_by_username, d.assigned_investigator, d.warrant_status, d.warrant_crime, d.warrant_classification, d.warrant_description, d.warrant_expires_at, d.risk_level, d.updated_at,
              COUNT(r.id) AS report_count
       FROM dossiers d
       LEFT JOIN reports r ON r.dossier_id = d.id
       WHERE d.assigned_investigator_user_id = ?
       GROUP BY d.id
       ORDER BY d.updated_at DESC`,
      [req.session.user.id]
    );
    res.render("my-assignments", { dossiers });
  } catch (error) {
    next(error);
  }
});

app.get("/login", (req, res) => {
  if (req.session?.user) {
    res.redirect("/");
    return;
  }
  res.render("login", { error: "" });
});

app.post("/login", async (req, res, next) => {
  try {
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    const user = await get("SELECT id, username, password_hash, role FROM users WHERE username = ?", [username]);
    if (!user) {
      res.status(401).render("login", { error: "Invalid credentials." });
      return;
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      res.status(401).render("login", { error: "Invalid credentials." });
      return;
    }

    req.session.user = { id: user.id, username: user.username, role: user.role || "analyst" };
    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.get("/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");
    res.render("admin-users", {
      users,
      error: "",
      success: "",
      form: { username: "", role: "analyst" },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";
    const role = (req.body.role || "analyst").trim();

    const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");

    if (!username || !password) {
      res.status(400).render("admin-users", {
        users,
        error: "Username and password are required.",
        success: "",
        form: { username, role },
      });
      return;
    }

    if (password.length < 8) {
      res.status(400).render("admin-users", {
        users,
        error: "Password must be at least 8 characters.",
        success: "",
        form: { username, role },
      });
      return;
    }

    if (!["admin", "lead_analyst", "analyst", "lead_internal_affairs", "internal_affairs"].includes(role)) {
      res.status(400).render("admin-users", {
        users,
        error: "Invalid role selected.",
        success: "",
        form: { username, role: "analyst" },
      });
      return;
    }

    const existingUser = await get("SELECT id FROM users WHERE username = ?", [username]);
    if (existingUser) {
      res.status(400).render("admin-users", {
        users,
        error: "Username already exists.",
        success: "",
        form: { username, role },
      });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, passwordHash, role]);

    const updatedUsers = await all("SELECT id, username, role FROM users ORDER BY username ASC");
    res.render("admin-users", {
      users: updatedUsers,
      error: "",
      success: `User ${username} created successfully.`,
      form: { username: "", role: "analyst" },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/admin/users/:id/delete", requireAdmin, async (req, res, next) => {
  try {
    const targetUserId = Number(req.params.id);
    const targetUser = await get("SELECT id, username, role FROM users WHERE id = ?", [targetUserId]);
    if (!targetUser) {
      const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");
      res.status(404).render("admin-users", {
        users,
        error: "User not found.",
        success: "",
        form: { username: "", role: "analyst" },
      });
      return;
    }

    if (targetUser.id === req.session.user.id) {
      const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");
      res.status(400).render("admin-users", {
        users,
        error: "You cannot delete your own account while logged in.",
        success: "",
        form: { username: "", role: "analyst" },
      });
      return;
    }

    if (targetUser.role === "admin") {
      const adminCountRow = await get("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'");
      if ((adminCountRow?.count || 0) <= 1) {
        const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");
        res.status(400).render("admin-users", {
          users,
          error: "Cannot delete the last remaining admin account.",
          success: "",
          form: { username: "", role: "analyst" },
        });
        return;
      }
    }

    await run("UPDATE dossiers SET created_by_user_id = NULL WHERE created_by_user_id = ?", [targetUser.id]);
    await run(
      "UPDATE dossiers SET assigned_investigator_user_id = NULL, assigned_investigator = '' WHERE assigned_investigator_user_id = ?",
      [targetUser.id]
    );
    await run("UPDATE ia_dossiers SET created_by_user_id = NULL WHERE created_by_user_id = ?", [targetUser.id]);
    await run(
      "UPDATE ia_dossiers SET assigned_investigator_user_id = NULL, assigned_investigator = '' WHERE assigned_investigator_user_id = ?",
      [targetUser.id]
    );

    // reports / ia_reports reference users with ON DELETE RESTRICT (Postgres). Reassign FK only; analyst_name stays the original author.
    const reassignTo = req.session.user.id;
    await run("UPDATE reports SET analyst_user_id = ? WHERE analyst_user_id = ?", [reassignTo, targetUser.id]);
    await run("UPDATE ia_reports SET analyst_user_id = ? WHERE analyst_user_id = ?", [reassignTo, targetUser.id]);

    await run("DELETE FROM users WHERE id = ?", [targetUser.id]);

    const users = await all("SELECT id, username, role FROM users ORDER BY username ASC");
    res.render("admin-users", {
      users,
      error: "",
      success: `User ${targetUser.username} deleted successfully.`,
      form: { username: "", role: "analyst" },
    });
  } catch (error) {
    next(error);
  }
});

app.post("/logout", requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      next(err);
      return;
    }
    res.redirect("/login");
  });
});

app.get("/account/password", requireAuth, (req, res) => {
  res.render("account-password", { error: "", success: "" });
});

app.post("/account/password", requireAuth, async (req, res, next) => {
  try {
    const currentPassword = (req.body.current_password || "").trim();
    const newPassword = (req.body.new_password || "").trim();
    const confirmPassword = (req.body.confirm_password || "").trim();

    if (!currentPassword || !newPassword || !confirmPassword) {
      res.status(400).render("account-password", {
        error: "Fill in all password fields.",
        success: "",
      });
      return;
    }
    if (newPassword !== confirmPassword) {
      res.status(400).render("account-password", {
        error: "New password and confirmation do not match.",
        success: "",
      });
      return;
    }
    if (newPassword.length < 8) {
      res.status(400).render("account-password", {
        error: "New password must be at least 8 characters.",
        success: "",
      });
      return;
    }

    const user = await get("SELECT * FROM users WHERE id = ?", [req.session.user.id]);
    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) {
      res.status(400).render("account-password", {
        error: "Current password is incorrect.",
        success: "",
      });
      return;
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await run("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, user.id]);
    res.render("account-password", { error: "", success: "Password updated successfully." });
  } catch (error) {
    next(error);
  }
});

app.get("/dossiers/new", requireAuth, (req, res) => {
  res.render("new-dossier", {
    error: "",
    form: {
      name: "",
      faction: factions[0],
      affiliation: "",
      notes: "",
      risk_level: "Low",
    },
  });
});

app.post("/dossiers", requireAuth, upload.single("screenshot"), async (req, res, next) => {
  try {
    const name = (req.body.name || "").trim();
    const faction = (req.body.faction || "").trim();
    const affiliation = (req.body.affiliation || "").trim();
    const notes = (req.body.notes || "").trim();
    const riskLevel = (req.body.risk_level || "").trim();
    const imagePath = req.file ? req.file.path || `/uploads/${req.file.filename}` : null;

    if (!name || !faction || !affiliation || !riskLevel) {
      res.status(400).render("new-dossier", {
        error: "Please complete all required fields.",
        form: {
          name,
          faction,
          affiliation,
          notes,
          risk_level: riskLevel,
        },
      });
      return;
    }

    if (!factions.includes(faction)) {
      res.status(400).render("new-dossier", {
        error: "Invalid faction selected.",
        form: {
          name,
          faction: factions[0],
          affiliation,
          notes,
          risk_level,
        },
      });
      return;
    }

    if (!riskLevels.includes(riskLevel)) {
      res.status(400).render("new-dossier", {
        error: "Invalid risk level selected.",
        form: {
          name,
          faction,
          affiliation,
          notes,
          risk_level: "Low",
        },
      });
      return;
    }

    const result = await run(
      `INSERT INTO dossiers
       (name, faction, affiliation, created_by_user_id, created_by_username, assigned_investigator_user_id, assigned_investigator, warrant_status, warrant_crime, warrant_description, warrant_expires_at, warrant_classification, risk_level, notes, image_path, updated_at)
       VALUES (?, ?, ?, ?, ?, NULL, '', 'none', '', '', NULL, '', ?, ?, ?, datetime('now'))`,
      [name, faction, affiliation, req.session.user.id, req.session.user.username, riskLevel, notes, imagePath]
    );

    res.redirect(`/dossiers/${result.lastID}`);
  } catch (error) {
    next(error);
  }
});

app.get("/dossiers/:id", requireAuth, async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    const reports = await all(
      `SELECT id, analyst_name, created_at, updated_at
       FROM reports
       WHERE dossier_id = ?
       ORDER BY created_at DESC`,
      [req.params.id]
    );
    const analysts = await getAssignableDossierInvestigators();
    res.render("dossier-detail", {
      dossier,
      message: "",
      reports,
      analysts,
      canAssign: canAssignMainDossier(req.session.user.role),
      canEditWarrant: canEditWarrant(req.session.user.role),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/notes", requireAuth, async (req, res, next) => {
  try {
    const notes = (req.body.notes || "").trim();
    await run("UPDATE dossiers SET notes = ?, updated_at = datetime('now') WHERE id = ?", [notes, req.params.id]);
    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    const reports = await all(
      `SELECT id, analyst_name, created_at, updated_at
       FROM reports
       WHERE dossier_id = ?
       ORDER BY created_at DESC`,
      [req.params.id]
    );
    const analysts = await getAssignableDossierInvestigators();
    res.render("dossier-detail", {
      dossier,
      message: "Notes updated.",
      reports,
      analysts,
      canAssign: canAssignMainDossier(req.session.user.role),
      canEditWarrant: canEditWarrant(req.session.user.role),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/warrants", requireAuth, async (req, res, next) => {
  try {
    if (!canEditWarrant(req.session.user.role)) {
      res.status(403).send("You do not have permission to update warrant activity.");
      return;
    }
    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const status = (req.body.warrant_status || "").trim();
    const crime = (req.body.warrant_crime || "").trim();
    const classification = (req.body.warrant_classification || "").trim();
    const description = (req.body.warrant_description || "").trim();
    const duration = (req.body.warrant_duration || "").trim();

    if (status !== "none" && status !== "active") {
      res.status(400).send("Invalid warrant status.");
      return;
    }

    let expiresAt = null;
    let crimeVal = "";
    let classVal = "";
    if (status === "active") {
      const validCrime = WARRANT_CRIMES.some((c) => c.value === crime);
      if (!validCrime) {
        res.status(400).send("Select a warrant type.");
        return;
      }
      if (classification && !WARRANT_CLASSIFICATIONS.some((c) => c.value === classification)) {
        res.status(400).send("Invalid classification.");
        return;
      }
      if (!WARRANT_DURATION_MS[duration]) {
        res.status(400).send("Select a warrant duration.");
        return;
      }
      crimeVal = crime;
      classVal = classification;
      expiresAt = computeExpiryIso(duration);
    }

    await run(
      `UPDATE dossiers SET warrant_status = ?, warrant_crime = ?, warrant_classification = ?, warrant_description = ?, warrant_expires_at = ?, updated_at = datetime('now') WHERE id = ?`,
      [status, crimeVal, classVal, description, expiresAt, req.params.id]
    );

    res.redirect(`/dossiers/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/assign", requireAuth, async (req, res, next) => {
  try {
    if (!canAssignMainDossier(req.session.user.role)) {
      res.status(403).send("Only lead analysts, lead internal affairs, or admins can assign dossiers.");
      return;
    }

    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const assignedUserId = Number(req.body.assigned_investigator_user_id || 0);
    const assignee = await get(
      "SELECT id, username FROM users WHERE id = ? AND role IN ('analyst', 'lead_analyst')",
      [assignedUserId]
    );
    if (!assignee) {
      res.status(400).send("Invalid investigator selected. Choose an analyst or lead analyst.");
      return;
    }

    await run(
      "UPDATE dossiers SET assigned_investigator_user_id = ?, assigned_investigator = ?, updated_at = datetime('now') WHERE id = ?",
      [assignee.id, assignee.username, req.params.id]
    );

    res.redirect(`/dossiers/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.get("/dossiers/:id/reports/new", requireAuth, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, name, faction, affiliation FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    res.render("report-form", {
      mode: "create",
      dossier,
      report: null,
      incidents: [{ incident_title: "", incident_datetime: "", incident_description: "", incident_outcome: "" }],
      error: "",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/reports", requireAuth, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, name, faction, affiliation FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const titles = Array.isArray(req.body.incident_title) ? req.body.incident_title : [req.body.incident_title];
    const datetimes = Array.isArray(req.body.incident_datetime) ? req.body.incident_datetime : [req.body.incident_datetime];
    const descriptions = Array.isArray(req.body.incident_description)
      ? req.body.incident_description
      : [req.body.incident_description];
    const outcomes = Array.isArray(req.body.incident_outcome) ? req.body.incident_outcome : [req.body.incident_outcome];

    const incidents = titles.map((title, i) => ({
      incident_title: (title || "").trim(),
      incident_datetime: (datetimes[i] || "").trim(),
      incident_description: (descriptions[i] || "").trim(),
      incident_outcome: (outcomes[i] || "").trim(),
    }));

    const validIncidents = incidents.filter(
      (incident) =>
        incident.incident_title &&
        incident.incident_datetime &&
        incident.incident_description &&
        incident.incident_outcome
    );

    if (validIncidents.length === 0) {
      res.status(400).render("report-form", {
        mode: "create",
        dossier,
        report: null,
        incidents,
        error: "Add at least one complete incident record.",
      });
      return;
    }

    const result = await run(
      `INSERT INTO reports
       (dossier_id, analyst_user_id, analyst_name, subject_name, subject_faction, subject_affiliation, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      [dossier.id, req.session.user.id, req.session.user.username, dossier.name, dossier.faction, dossier.affiliation]
    );

    for (let i = 0; i < validIncidents.length; i += 1) {
      const incident = validIncidents[i];
      await run(
        `INSERT INTO report_incidents
         (report_id, incident_order, incident_title, incident_datetime, incident_description, incident_outcome)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          result.lastID,
          i + 1,
          incident.incident_title,
          incident.incident_datetime,
          incident.incident_description,
          incident.incident_outcome,
        ]
      );
    }

    res.redirect(`/reports/${result.lastID}`);
  } catch (error) {
    next(error);
  }
});

app.get("/reports/:id", requireAuth, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    const incidents = await all(
      `SELECT incident_title, incident_datetime, incident_description, incident_outcome
       FROM report_incidents
       WHERE report_id = ?
       ORDER BY incident_order ASC`,
      [report.id]
    );
    res.render("report-view", {
      report,
      incidents,
      canEdit: req.session.user.id === report.analyst_user_id,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/reports/:id/edit", requireAuth, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    if (req.session.user.id !== report.analyst_user_id) {
      res.status(403).send("Only the report author can edit this report.");
      return;
    }
    const incidents = await all(
      `SELECT incident_title, incident_datetime, incident_description, incident_outcome
       FROM report_incidents
       WHERE report_id = ?
       ORDER BY incident_order ASC`,
      [report.id]
    );
    const dossier = {
      id: report.dossier_id,
      name: report.subject_name,
      faction: report.subject_faction,
      affiliation: report.subject_affiliation,
    };
    res.render("report-form", {
      mode: "edit",
      dossier,
      report,
      incidents:
        incidents.length > 0
          ? incidents
          : [{ incident_title: "", incident_datetime: "", incident_description: "", incident_outcome: "" }],
      error: "",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/reports/:id/edit", requireAuth, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    if (req.session.user.id !== report.analyst_user_id) {
      res.status(403).send("Only the report author can edit this report.");
      return;
    }

    const titles = Array.isArray(req.body.incident_title) ? req.body.incident_title : [req.body.incident_title];
    const datetimes = Array.isArray(req.body.incident_datetime) ? req.body.incident_datetime : [req.body.incident_datetime];
    const descriptions = Array.isArray(req.body.incident_description)
      ? req.body.incident_description
      : [req.body.incident_description];
    const outcomes = Array.isArray(req.body.incident_outcome) ? req.body.incident_outcome : [req.body.incident_outcome];

    const incidents = titles.map((title, i) => ({
      incident_title: (title || "").trim(),
      incident_datetime: (datetimes[i] || "").trim(),
      incident_description: (descriptions[i] || "").trim(),
      incident_outcome: (outcomes[i] || "").trim(),
    }));
    const validIncidents = incidents.filter(
      (incident) =>
        incident.incident_title &&
        incident.incident_datetime &&
        incident.incident_description &&
        incident.incident_outcome
    );

    const dossier = {
      id: report.dossier_id,
      name: report.subject_name,
      faction: report.subject_faction,
      affiliation: report.subject_affiliation,
    };

    if (validIncidents.length === 0) {
      res.status(400).render("report-form", {
        mode: "edit",
        dossier,
        report,
        incidents,
        error: "Add at least one complete incident record.",
      });
      return;
    }

    await run("DELETE FROM report_incidents WHERE report_id = ?", [report.id]);
    for (let i = 0; i < validIncidents.length; i += 1) {
      const incident = validIncidents[i];
      await run(
        `INSERT INTO report_incidents
         (report_id, incident_order, incident_title, incident_datetime, incident_description, incident_outcome)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [report.id, i + 1, incident.incident_title, incident.incident_datetime, incident.incident_description, incident.incident_outcome]
      );
    }
    await run("UPDATE reports SET updated_at = datetime('now') WHERE id = ?", [report.id]);

    res.redirect(`/reports/${report.id}`);
  } catch (error) {
    next(error);
  }
});

app.get("/dossiers/:id/edit", requireAuth, async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    res.render("edit-dossier", { dossier, error: "" });
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/edit", requireAuth, upload.single("screenshot"), async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const name = (req.body.name || "").trim();
    const faction = (req.body.faction || "").trim();
    const affiliation = (req.body.affiliation || "").trim();
    const riskLevel = (req.body.risk_level || "").trim();
    const imagePath = req.file ? req.file.path || `/uploads/${req.file.filename}` : dossier.image_path;

    if (!name || !faction || !affiliation || !riskLevel) {
      res.status(400).render("edit-dossier", {
        dossier: {
          ...dossier,
          name,
          faction,
          affiliation,
          risk_level: riskLevel,
        },
        error: "Please complete all required fields.",
      });
      return;
    }

    if (!factions.includes(faction) || !riskLevels.includes(riskLevel)) {
      res.status(400).render("edit-dossier", {
        dossier: {
          ...dossier,
          name,
          faction,
          affiliation,
          risk_level: riskLevel,
        },
        error: "Invalid faction or risk level.",
      });
      return;
    }

    await run(
      `UPDATE dossiers
       SET name = ?, faction = ?, affiliation = ?, risk_level = ?, image_path = ?, updated_at = datetime('now')
       WHERE id = ?`,
      [name, faction, affiliation, riskLevel, imagePath, req.params.id]
    );

    res.redirect(`/dossiers/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/dossiers/:id/delete", requireAdmin, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, image_path FROM dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const reports = await all("SELECT id FROM reports WHERE dossier_id = ?", [req.params.id]);
    for (const report of reports) {
      await run("DELETE FROM report_incidents WHERE report_id = ?", [report.id]);
    }
    await run("DELETE FROM reports WHERE dossier_id = ?", [req.params.id]);
    await run("DELETE FROM dossiers WHERE id = ?", [req.params.id]);

    if (dossier.image_path && dossier.image_path.startsWith("/uploads/")) {
      const imageFilePath = path.join(__dirname, dossier.image_path.replace("/uploads/", "uploads/"));
      if (fs.existsSync(imageFilePath)) {
        fs.unlinkSync(imageFilePath);
      }
    }

    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.get("/ia", requireIaAccess, async (req, res, next) => {
  try {
    const name = (req.query.name || "").trim();
    const faction = (req.query.faction || "").trim();
    const risk = (req.query.risk || "").trim();
    const where = [];
    const params = [];
    if (name) {
      where.push("d.name LIKE ?");
      params.push(`%${name}%`);
    }
    if (faction) {
      where.push("d.faction = ?");
      params.push(faction);
    }
    if (risk) {
      where.push("d.risk_level = ?");
      params.push(risk);
    }
    const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const dossiers = await all(
      `SELECT d.id, d.name, d.faction, d.affiliation, d.created_by_username, d.assigned_investigator, d.warrant_status, d.warrant_crime, d.warrant_classification, d.warrant_description, d.warrant_expires_at, d.risk_level, d.notes, d.image_path, d.created_at, d.updated_at,
              COUNT(r.id) AS report_count
       FROM ia_dossiers d
       LEFT JOIN ia_reports r ON r.dossier_id = d.id
       ${whereClause}
       GROUP BY d.id
       ORDER BY d.updated_at DESC`,
      params
    );
    res.render("ia-index", { dossiers, filters: { name, faction, risk } });
  } catch (error) {
    next(error);
  }
});

app.get("/ia/new", requireIaAccess, (req, res) => {
  res.render("ia-new-dossier", {
    error: "",
    form: { name: "", faction: factions[0], affiliation: "", notes: "", risk_level: "Low" },
  });
});

app.post("/ia", requireIaAccess, upload.single("screenshot"), async (req, res, next) => {
  try {
    const name = (req.body.name || "").trim();
    const faction = (req.body.faction || "").trim();
    const affiliation = (req.body.affiliation || "").trim();
    const notes = (req.body.notes || "").trim();
    const riskLevel = (req.body.risk_level || "").trim();
    const imagePath = req.file ? req.file.path || `/uploads/${req.file.filename}` : null;
    if (!name || !faction || !affiliation || !riskLevel) {
      res.status(400).render("ia-new-dossier", {
        error: "Please complete all required fields.",
        form: { name, faction, affiliation, notes, risk_level: riskLevel },
      });
      return;
    }
    if (!factions.includes(faction) || !riskLevels.includes(riskLevel)) {
      res.status(400).render("ia-new-dossier", {
        error: "Invalid faction or risk level selected.",
        form: { name, faction: factions[0], affiliation, notes, risk_level: "Low" },
      });
      return;
    }
    const result = await run(
      `INSERT INTO ia_dossiers
       (name, faction, affiliation, created_by_user_id, created_by_username, assigned_investigator_user_id, assigned_investigator, warrant_status, warrant_crime, warrant_description, warrant_expires_at, warrant_classification, risk_level, notes, image_path, updated_at)
       VALUES (?, ?, ?, ?, ?, NULL, '', 'none', '', '', NULL, '', ?, ?, ?, datetime('now'))`,
      [name, faction, affiliation, req.session.user.id, req.session.user.username, riskLevel, notes, imagePath]
    );
    res.redirect(`/ia/${result.lastID}`);
  } catch (error) {
    next(error);
  }
});

app.get("/ia/assignments/my", requireIaAccess, async (req, res, next) => {
  try {
    const dossiers = await all(
      `SELECT d.id, d.name, d.faction, d.affiliation, d.created_by_username, d.assigned_investigator, d.warrant_status, d.warrant_crime, d.warrant_classification, d.warrant_description, d.warrant_expires_at, d.risk_level, d.updated_at,
              COUNT(r.id) AS report_count
       FROM ia_dossiers d
       LEFT JOIN ia_reports r ON r.dossier_id = d.id
       WHERE d.assigned_investigator_user_id = ?
       GROUP BY d.id
       ORDER BY d.updated_at DESC`,
      [req.session.user.id]
    );
    res.render("ia-my-assignments", { dossiers });
  } catch (error) {
    next(error);
  }
});

app.get("/ia/reports/my", requireIaAccess, async (req, res, next) => {
  try {
    const reports = await all(
      `SELECT r.id, r.analyst_name, r.subject_name, r.subject_faction, r.subject_affiliation, r.created_at, r.updated_at, r.dossier_id,
              COUNT(ri.id) AS incident_count
       FROM ia_reports r
       LEFT JOIN ia_report_incidents ri ON ri.report_id = r.id
       WHERE r.analyst_user_id = ?
       GROUP BY r.id
       ORDER BY r.updated_at DESC`,
      [req.session.user.id]
    );
    res.render("ia-my-reports", { reports });
  } catch (error) {
    next(error);
  }
});

app.get("/ia/:id", requireIaAccess, async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    const reports = await all(
      `SELECT id, analyst_name, created_at, updated_at
       FROM ia_reports
       WHERE dossier_id = ?
       ORDER BY created_at DESC`,
      [req.params.id]
    );
    const analysts = await getAssignableIaAgents();
    res.render("ia-dossier-detail", {
      dossier,
      message: "",
      reports,
      analysts,
      canAssign: canAssignIa(req),
      canEditWarrant: canEditWarrant(req.session.user.role),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/notes", requireIaAccess, async (req, res, next) => {
  try {
    const notes = (req.body.notes || "").trim();
    await run("UPDATE ia_dossiers SET notes = ?, updated_at = datetime('now') WHERE id = ?", [notes, req.params.id]);
    res.redirect(`/ia/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/warrants", requireIaAccess, async (req, res, next) => {
  try {
    if (!canEditWarrant(req.session.user.role)) {
      res.status(403).send("You do not have permission to update warrant activity.");
      return;
    }
    const dossier = await get("SELECT * FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const status = (req.body.warrant_status || "").trim();
    const crime = (req.body.warrant_crime || "").trim();
    const classification = (req.body.warrant_classification || "").trim();
    const description = (req.body.warrant_description || "").trim();
    const duration = (req.body.warrant_duration || "").trim();

    if (status !== "none" && status !== "active") {
      res.status(400).send("Invalid warrant status.");
      return;
    }

    let expiresAt = null;
    let crimeVal = "";
    let classVal = "";
    if (status === "active") {
      const validCrime = WARRANT_CRIMES.some((c) => c.value === crime);
      if (!validCrime) {
        res.status(400).send("Select a warrant type.");
        return;
      }
      if (classification && !WARRANT_CLASSIFICATIONS.some((c) => c.value === classification)) {
        res.status(400).send("Invalid classification.");
        return;
      }
      if (!WARRANT_DURATION_MS[duration]) {
        res.status(400).send("Select a warrant duration.");
        return;
      }
      crimeVal = crime;
      classVal = classification;
      expiresAt = computeExpiryIso(duration);
    }

    await run(
      `UPDATE ia_dossiers SET warrant_status = ?, warrant_crime = ?, warrant_classification = ?, warrant_description = ?, warrant_expires_at = ?, updated_at = datetime('now') WHERE id = ?`,
      [status, crimeVal, classVal, description, expiresAt, req.params.id]
    );

    res.redirect(`/ia/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/assign", requireIaAccess, async (req, res, next) => {
  try {
    if (!canAssignIa(req)) {
      res.status(403).send("Only lead IA or admins can assign IA dossiers.");
      return;
    }
    const assignedUserId = Number(req.body.assigned_investigator_user_id || 0);
    const analyst = await get(
      "SELECT id, username FROM users WHERE id = ? AND role IN ('internal_affairs', 'lead_internal_affairs')",
      [assignedUserId]
    );
    if (!analyst) {
      res.status(400).send("Invalid IA user selected.");
      return;
    }
    await run(
      "UPDATE ia_dossiers SET assigned_investigator_user_id = ?, assigned_investigator = ?, updated_at = datetime('now') WHERE id = ?",
      [analyst.id, analyst.username, req.params.id]
    );
    res.redirect(`/ia/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.get("/ia/:id/edit", requireIaAccess, async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    res.render("ia-edit-dossier", { dossier, error: "" });
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/edit", requireIaAccess, upload.single("screenshot"), async (req, res, next) => {
  try {
    const dossier = await get("SELECT * FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    const name = (req.body.name || "").trim();
    const faction = (req.body.faction || "").trim();
    const affiliation = (req.body.affiliation || "").trim();
    const riskLevel = (req.body.risk_level || "").trim();
    const imagePath = req.file ? req.file.path || `/uploads/${req.file.filename}` : dossier.image_path;
    if (!name || !faction || !affiliation || !riskLevel) {
      res.status(400).render("ia-edit-dossier", {
        dossier: { ...dossier, name, faction, affiliation, risk_level: riskLevel },
        error: "Please complete all required fields.",
      });
      return;
    }
    if (!factions.includes(faction) || !riskLevels.includes(riskLevel)) {
      res.status(400).render("ia-edit-dossier", {
        dossier: { ...dossier, name, faction, affiliation, risk_level: riskLevel },
        error: "Invalid faction or risk level.",
      });
      return;
    }
    await run(
      `UPDATE ia_dossiers
       SET name = ?, faction = ?, affiliation = ?, risk_level = ?, image_path = ?, updated_at = datetime('now')
       WHERE id = ?`,
      [name, faction, affiliation, riskLevel, imagePath, req.params.id]
    );
    res.redirect(`/ia/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/delete", requireAdmin, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, image_path FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }

    const reports = await all("SELECT id FROM ia_reports WHERE dossier_id = ?", [req.params.id]);
    for (const report of reports) {
      await run("DELETE FROM ia_report_incidents WHERE report_id = ?", [report.id]);
    }
    await run("DELETE FROM ia_reports WHERE dossier_id = ?", [req.params.id]);
    await run("DELETE FROM ia_dossiers WHERE id = ?", [req.params.id]);

    if (dossier.image_path && dossier.image_path.startsWith("/uploads/")) {
      const imageFilePath = path.join(__dirname, dossier.image_path.replace("/uploads/", "uploads/"));
      if (fs.existsSync(imageFilePath)) {
        fs.unlinkSync(imageFilePath);
      }
    }

    res.redirect("/ia");
  } catch (error) {
    next(error);
  }
});

app.get("/ia/:id/reports/new", requireIaAccess, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, name, faction, affiliation FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    res.render("ia-report-form", {
      mode: "create",
      dossier,
      report: null,
      incidents: [{ incident_title: "", incident_datetime: "", incident_description: "", incident_outcome: "" }],
      error: "",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/ia/:id/reports", requireIaAccess, async (req, res, next) => {
  try {
    const dossier = await get("SELECT id, name, faction, affiliation FROM ia_dossiers WHERE id = ?", [req.params.id]);
    if (!dossier) {
      res.status(404).send("Dossier not found.");
      return;
    }
    const titles = Array.isArray(req.body.incident_title) ? req.body.incident_title : [req.body.incident_title];
    const datetimes = Array.isArray(req.body.incident_datetime) ? req.body.incident_datetime : [req.body.incident_datetime];
    const descriptions = Array.isArray(req.body.incident_description) ? req.body.incident_description : [req.body.incident_description];
    const outcomes = Array.isArray(req.body.incident_outcome) ? req.body.incident_outcome : [req.body.incident_outcome];
    const incidents = titles.map((title, i) => ({
      incident_title: (title || "").trim(),
      incident_datetime: (datetimes[i] || "").trim(),
      incident_description: (descriptions[i] || "").trim(),
      incident_outcome: (outcomes[i] || "").trim(),
    }));
    const validIncidents = incidents.filter((x) => x.incident_title && x.incident_datetime && x.incident_description && x.incident_outcome);
    if (validIncidents.length === 0) {
      res.status(400).render("ia-report-form", { mode: "create", dossier, report: null, incidents, error: "Add at least one complete incident record." });
      return;
    }
    const result = await run(
      `INSERT INTO ia_reports
       (dossier_id, analyst_user_id, analyst_name, subject_name, subject_faction, subject_affiliation, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
      [dossier.id, req.session.user.id, req.session.user.username, dossier.name, dossier.faction, dossier.affiliation]
    );
    for (let i = 0; i < validIncidents.length; i += 1) {
      const incident = validIncidents[i];
      await run(
        `INSERT INTO ia_report_incidents
         (report_id, incident_order, incident_title, incident_datetime, incident_description, incident_outcome)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [result.lastID, i + 1, incident.incident_title, incident.incident_datetime, incident.incident_description, incident.incident_outcome]
      );
    }
    res.redirect(`/ia/reports/${result.lastID}`);
  } catch (error) {
    next(error);
  }
});

app.get("/ia/reports/:id", requireIaAccess, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM ia_reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    const incidents = await all(
      `SELECT incident_title, incident_datetime, incident_description, incident_outcome
       FROM ia_report_incidents
       WHERE report_id = ?
       ORDER BY incident_order ASC`,
      [report.id]
    );
    res.render("ia-report-view", { report, incidents, canEdit: req.session.user.id === report.analyst_user_id });
  } catch (error) {
    next(error);
  }
});

app.get("/ia/reports/:id/edit", requireIaAccess, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM ia_reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    if (req.session.user.id !== report.analyst_user_id) {
      res.status(403).send("Only the report author can edit this report.");
      return;
    }
    const incidents = await all(
      `SELECT incident_title, incident_datetime, incident_description, incident_outcome
       FROM ia_report_incidents
       WHERE report_id = ?
       ORDER BY incident_order ASC`,
      [report.id]
    );
    const dossier = { id: report.dossier_id, name: report.subject_name, faction: report.subject_faction, affiliation: report.subject_affiliation };
    res.render("ia-report-form", {
      mode: "edit",
      dossier,
      report,
      incidents: incidents.length ? incidents : [{ incident_title: "", incident_datetime: "", incident_description: "", incident_outcome: "" }],
      error: "",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/ia/reports/:id/edit", requireIaAccess, async (req, res, next) => {
  try {
    const report = await get("SELECT * FROM ia_reports WHERE id = ?", [req.params.id]);
    if (!report) {
      res.status(404).send("Report not found.");
      return;
    }
    if (req.session.user.id !== report.analyst_user_id) {
      res.status(403).send("Only the report author can edit this report.");
      return;
    }
    const titles = Array.isArray(req.body.incident_title) ? req.body.incident_title : [req.body.incident_title];
    const datetimes = Array.isArray(req.body.incident_datetime) ? req.body.incident_datetime : [req.body.incident_datetime];
    const descriptions = Array.isArray(req.body.incident_description) ? req.body.incident_description : [req.body.incident_description];
    const outcomes = Array.isArray(req.body.incident_outcome) ? req.body.incident_outcome : [req.body.incident_outcome];
    const incidents = titles.map((title, i) => ({
      incident_title: (title || "").trim(),
      incident_datetime: (datetimes[i] || "").trim(),
      incident_description: (descriptions[i] || "").trim(),
      incident_outcome: (outcomes[i] || "").trim(),
    }));
    const validIncidents = incidents.filter((x) => x.incident_title && x.incident_datetime && x.incident_description && x.incident_outcome);
    if (validIncidents.length === 0) {
      const dossier = { id: report.dossier_id, name: report.subject_name, faction: report.subject_faction, affiliation: report.subject_affiliation };
      res.status(400).render("ia-report-form", { mode: "edit", dossier, report, incidents, error: "Add at least one complete incident record." });
      return;
    }
    await run("DELETE FROM ia_report_incidents WHERE report_id = ?", [report.id]);
    for (let i = 0; i < validIncidents.length; i += 1) {
      const incident = validIncidents[i];
      await run(
        `INSERT INTO ia_report_incidents
         (report_id, incident_order, incident_title, incident_datetime, incident_description, incident_outcome)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [report.id, i + 1, incident.incident_title, incident.incident_datetime, incident.incident_description, incident.incident_outcome]
      );
    }
    await run("UPDATE ia_reports SET updated_at = datetime('now') WHERE id = ?", [report.id]);
    res.redirect(`/ia/reports/${report.id}`);
  } catch (error) {
    next(error);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send("Internal server error.");
});

initializeDatabase()
  .then(() => {
    app.listen(port, () => {
      console.log(`Intelligence app running at http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error("Failed to initialize database:", error);
    process.exit(1);
  });
