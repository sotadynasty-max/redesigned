# Dear Diary

An account-based diary with private letters stored in PostgreSQL. Each letter API operation is scoped to the signed-in account. Passwords are hashed with bcrypt, and the app uses server-side sessions, HTTP-only cookies, CSRF protection, and rate-limited sign-in/sign-up endpoints.

## Run locally

1. Install Node.js 20 or newer and PostgreSQL.
2. Create a PostgreSQL database named `dear_diary`.
3. Copy `.env.example` to `.env` and set `DATABASE_URL` to your local database connection string. Set `SESSION_SECRET` to a random value with at least 32 characters.
4. Run `npm install`, then run `npm start`. The app reads its settings from `.env`.
5. Open `http://localhost:3000`.

The server creates its tables on first start. Keep `.env` private and do not commit it.

## Deploy to Render

Push this repository to GitHub first. If Render does not offer a Blueprint option, create the database and web service separately:

1. In the Render dashboard, create a **PostgreSQL** database. Choose a persistent paid plan if you need to keep diary entries long-term; free databases may expire. Keep the database in the same region as the web service.
2. Create a **Web Service** and connect this GitHub repository and the branch to deploy. Use the repository root as the root directory, select the Node runtime, and set:
   - Build command: `npm ci`
   - Start command: `npm start`
3. In the web service's environment settings, add `NODE_ENV` with value `production`, `DATABASE_URL` with the database's **Internal Database URL**, and `SESSION_SECRET` with a private random value of at least 32 characters.
4. Set the web service's health check path to `/healthz`, then create/deploy the service. Wait for the deployment and health check to succeed before opening its URL.

The app listens on Render's assigned port and creates its database tables on startup. After the first deployment, pushes to the connected branch are deployed automatically when auto-deploy is enabled in the service settings. The included `render.yaml` is an optional Blueprint configuration; it is not required for the manual setup above.

The web service is configured as a free instance, which can spin down when idle; the first request after inactivity may take a little longer. Check Render's current pricing before creating resources.

## Privacy and account notes

Letters are not public and are returned only to the account that owns them. Use a unique, strong password and keep the Render account, repository, and database private. This app does not yet send email verification or password-reset messages; if a user forgets their password, an administrator would need to handle recovery. Email addresses are used as account identifiers but are not verified.

Letters are not end-to-end encrypted: the hosting provider and anyone with database or server access could access stored data. The app protects access between accounts, but it is not a zero-knowledge vault. Back up the PostgreSQL database regularly.
