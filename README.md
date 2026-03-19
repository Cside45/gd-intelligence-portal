# GD Intelligence Dossier Web App

Password-protected dossier manager for creating and searching intelligence profiles.

## Features

- Session-based login with seeded admin account
- Admin-only user management page for creating accounts and roles
- Roles: `admin`, `lead_analyst`, `analyst`, `lead_internal_affairs`, `internal_affairs`
- Create dossier entries with:
  - Screenshot image upload
  - Name
  - Faction
  - Affiliation
  - Creator is automatically recorded
  - Previous warrants
  - Risk level (`Low`, `Medium`, `High`)
  - Notes
- Search/filter by:
  - Name
  - Faction
  - Risk level
- Notes can be edited at any time from the dossier page
- Core fields are editable via a separate correction flow
- In-depth reports per dossier with:
  - Header (analyst name + creation time)
  - Subject profile snapshot (name, faction, affiliation)
  - Multiple incident records
  - Visible to all analysts, editable only by report author
- Analyst "My Reports" page showing reports authored by current user
- Dossier cards include report count indicators
- "My Assignments" page showing dossiers assigned to the logged-in analyst
- Assignment is lead/admin controlled via analyst dropdown on dossier detail
- Separate Internal Affairs section at `/ia` with isolated IA dossiers/reports
- IA content access restricted to admin and IA roles only

## Local Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create `.env` from `.env.example` and set secure values:

   ```env
   PORT=3000
   SESSION_SECRET=your-long-random-secret
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your-secure-password
   ```

3. Run the app:

   ```bash
   npm start
   ```

4. Open [http://localhost:3000](http://localhost:3000)

## Fast Public Deployment (Render + Supabase + Cloudinary)

1. Create free accounts:
   - [Render](https://render.com/)
   - [Supabase](https://supabase.com/) (for database)
   - [Cloudinary](https://cloudinary.com/) (for image uploads)

2. In Supabase:
   - Create a new project.
   - For **Render** (and other IPv4-only hosts): open **Connect** → **Connection string** → choose **Session pooler**, port **5432**. Use that URI as `DATABASE_URL` (host looks like `aws-0-REGION.pooler.supabase.com`, user like `postgres.PROJECT_REF`). The direct `db.*.supabase.co` URL is **IPv6-only** and will not work on Render unless you buy Supabase’s IPv4 add-on.

3. In Cloudinary:
   - Copy `Cloud name`, `API key`, `API secret` from dashboard.

4. Push this project to GitHub.

5. In Render:
   - New -> Web Service -> connect your GitHub repo.
   - Build command: `npm install`
   - Start command: `npm start`
   - Add environment variables:
     - `SESSION_SECRET` (long random string)
     - `ADMIN_USERNAME`
     - `ADMIN_PASSWORD`
     - `DATABASE_URL` (from Supabase)
     - `PGSSL=true`
     - `CLOUDINARY_CLOUD_NAME`
     - `CLOUDINARY_API_KEY`
     - `CLOUDINARY_API_SECRET`

6. Click **Deploy**. Render gives a public URL you can share immediately.

7. First login uses your configured admin credentials from Render env vars.

## Notes

- If `DATABASE_URL` is set, the app uses Postgres automatically (recommended for hosting).
- If `DATABASE_URL` is not set, the app uses local SQLite at `data/intelligence.db`.
- If Cloudinary keys are set, uploads are stored in Cloudinary.
- If Cloudinary keys are missing, uploads are stored locally in `uploads/`.

### Deploy: Supabase on Render (`ENETUNREACH` / no IPv4)

Supabase’s **direct** host `db.<ref>.supabase.co` is **IPv6-only** by default. Render has **no IPv6 route**, so you must use one of:

1. **Session pooler** (free, IPv4): Supabase **Connect** → **Connection string** → **Session pooler** → port `5432`. Set that full URI as `DATABASE_URL`.
2. **IPv4 add-on** (paid) on Supabase if you need the direct host.

This app resolves an **A record** and connects by IPv4 when possible; it will error with a clear message if the host has no IPv4. Use `PG_ALLOW_IPV6=true` only on IPv6-capable networks.
