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
   - Copy the Postgres connection string from **Project Settings -> Database**.

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

### Deploy: `ENETUNREACH` to Supabase (IPv6)

Some platforms resolve `db.*.supabase.co` to **IPv6** first; if the host has no IPv6 route you may see:

`Error: connect ENETUNREACH ... :5432`

This repo sets **IPv4-first DNS** when connecting to Postgres (Node 17+). If you still see errors, on Render add:

`NODE_OPTIONS` = `--dns-result-order=ipv4first`

Or use Supabase’s **Session pooler** connection string (from **Database → Connection string**) instead of the direct DB host.
