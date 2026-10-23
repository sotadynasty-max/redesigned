"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { Pool } = require("pg");

const requiredEnvironment = ["DATABASE_URL", "SESSION_SECRET"];
for (const name of requiredEnvironment) {
    if (!process.env[name]) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
}
if (process.env.SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET must contain at least 32 characters.");
}

const isProduction = process.env.NODE_ENV === "production";
const port = Number(process.env.PORT) || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();
const PgStore = connectPgSimple(session);

if (isProduction) app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:"],
            "object-src": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'none'"]
        }
    }
}));
app.use(express.json({ limit: "512kb" }));
app.use(session({
    name: "dear-diary.sid",
    store: new PgStore({
        pool,
        createTableIfMissing: true,
        tableName: "user_sessions"
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: "lax",
        maxAge: 14 * 24 * 60 * 60 * 1000
    }
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many attempts. Please wait a little while and try again." }
});

function newCsrfToken() {
    return crypto.randomBytes(32).toString("hex");
}

function csrfProtection(req, res, next) {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();

    const provided = req.get("x-csrf-token");
    const expected = req.session && req.session.csrfToken;
    if (typeof provided !== "string" || typeof expected !== "string") {
        return res.status(403).json({ error: "Your session expired. Refresh the page and try again." });
    }

    const providedBuffer = Buffer.from(provided);
    const expectedBuffer = Buffer.from(expected);
    if (providedBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(providedBuffer, expectedBuffer)) {
        return res.status(403).json({ error: "Your session expired. Refresh the page and try again." });
    }
    return next();
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: "Please sign in to continue." });
    }
    return next();
}

function validEmail(value) {
    return typeof value === "string" &&
        value.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validDate(value) {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const date = new Date(`${value}T00:00:00.000Z`);
    return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function validLetter(payload) {
    return payload &&
        typeof payload.title === "string" &&
        payload.title.length <= 120 &&
        typeof payload.body === "string" &&
        payload.body.length <= 100000 &&
        validDate(payload.date) &&
        (payload.title.trim().length > 0 || payload.body.trim().length > 0);
}

function validId(value) {
    return typeof value === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function serializeLetter(row) {
    return {
        id: row.id,
        title: row.title,
        body: row.body,
        date: row.entry_date instanceof Date
            ? row.entry_date.toISOString().slice(0, 10)
            : String(row.entry_date).slice(0, 10),
        updatedAt: new Date(row.updated_at).getTime()
    };
}

function saveSession(req) {
    return new Promise((resolve, reject) => {
        req.session.save((error) => error ? reject(error) : resolve());
    });
}

function regenerateSession(req) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => error ? reject(error) : resolve());
    });
}

app.use("/api", csrfProtection);

app.get("/healthz", (_req, res) => res.status(200).send("ok"));

app.get("/api/csrf", (req, res) => {
    if (!req.session.csrfToken) req.session.csrfToken = newCsrfToken();
    res.json({ csrfToken: req.session.csrfToken });
});

app.get("/api/auth/me", async (req, res, next) => {
    if (!req.session.userId) return res.json({ user: null });
    try {
        const result = await pool.query(
            "SELECT id, email FROM diary_users WHERE id = $1",
            [req.session.userId]
        );
        if (!result.rowCount) {
            return req.session.destroy((error) => {
                if (error) return next(error);
                return res.json({ user: null });
            });
        }
        return res.json({ user: result.rows[0] });
    } catch (error) {
        return next(error);
    }
});

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
    const payload = req.body || {};
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    const password = payload.password;
    if (!validEmail(email) || typeof password !== "string" ||
        password.length < 12 || password.length > 128) {
        return res.status(400).json({
            error: "Enter a valid email and a password between 12 and 128 characters."
        });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const result = await pool.query(
            "INSERT INTO diary_users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
            [email, passwordHash]
        );
        await signIn(req, res, result.rows[0]);
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({ error: "An account with this email already exists." });
        }
        return next(error);
    }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
    const payload = req.body || {};
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    const password = payload.password;
    if (!validEmail(email) || typeof password !== "string" ||
        password.length < 1 || password.length > 128) {
        return res.status(400).json({ error: "Enter your email and password." });
    }

    try {
        const result = await pool.query(
            "SELECT id, email, password_hash FROM diary_users WHERE email = $1",
            [email]
        );
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: "Email or password is incorrect." });
        }
        await signIn(req, res, user);
    } catch (error) {
        return next(error);
    }
});

async function signIn(req, res, user) {
    try {
        await regenerateSession(req);
        req.session.userId = user.id;
        req.session.csrfToken = newCsrfToken();
        await saveSession(req);
        res.json({
            user: { id: user.id, email: user.email },
            csrfToken: req.session.csrfToken
        });
    } catch (error) {
        console.error("Unable to establish a user session.", error);
        res.status(500).json({ error: "Unable to sign in right now. Please try again." });
    }
}

app.post("/api/auth/logout", requireAuth, async (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);
        res.clearCookie("dear-diary.sid", {
            httpOnly: true,
            secure: isProduction,
            sameSite: "lax"
        });
        return res.status(204).end();
    });
});

app.get("/api/letters", requireAuth, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, title, body, entry_date, updated_at
             FROM diary_letters
             WHERE user_id = $1
             ORDER BY updated_at DESC`,
            [req.session.userId]
        );
        res.json({ letters: result.rows.map(serializeLetter) });
    } catch (error) {
        next(error);
    }
});

app.post("/api/letters", requireAuth, async (req, res, next) => {
    if (!validLetter(req.body)) {
        return res.status(400).json({ error: "Add a title or letter and choose a valid date." });
    }
    try {
        const result = await pool.query(
            `INSERT INTO diary_letters (user_id, title, body, entry_date)
             VALUES ($1, $2, $3, $4)
             RETURNING id, title, body, entry_date, updated_at`,
            [req.session.userId, req.body.title.trim(), req.body.body, req.body.date]
        );
        res.status(201).json({ letter: serializeLetter(result.rows[0]) });
    } catch (error) {
        next(error);
    }
});

app.put("/api/letters/:id", requireAuth, async (req, res, next) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid letter." });
    if (!validLetter(req.body)) {
        return res.status(400).json({ error: "Add a title or letter and choose a valid date." });
    }
    try {
        const result = await pool.query(
            `UPDATE diary_letters
             SET title = $1, body = $2, entry_date = $3, updated_at = NOW()
             WHERE id = $4 AND user_id = $5
             RETURNING id, title, body, entry_date, updated_at`,
            [req.body.title.trim(), req.body.body, req.body.date, req.params.id, req.session.userId]
        );
        if (!result.rowCount) return res.status(404).json({ error: "Letter not found." });
        res.json({ letter: serializeLetter(result.rows[0]) });
    } catch (error) {
        next(error);
    }
});

app.delete("/api/letters/:id", requireAuth, async (req, res, next) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: "Invalid letter." });
    try {
        const result = await pool.query(
            "DELETE FROM diary_letters WHERE id = $1 AND user_id = $2",
            [req.params.id, req.session.userId]
        );
        if (!result.rowCount) return res.status(404).json({ error: "Letter not found." });
        res.status(204).end();
    } catch (error) {
        next(error);
    }
});

app.use(express.static(path.join(__dirname, "public"), {
    index: "index.html",
    maxAge: isProduction ? "1h" : 0,
    setHeaders(res, filePath) {
        if (path.basename(filePath) === "index.html") {
            res.setHeader("Cache-Control", "no-store");
        }
    }
}));

app.use((error, req, res, _next) => {
    if (res.headersSent) return;
    if (error.type === "entity.parse.failed") {
        return res.status(400).json({ error: "The request contains invalid JSON." });
    }
    if (error.type === "entity.too.large") {
        return res.status(413).json({ error: "The request is too large." });
    }
    console.error("Request failed.", error);
    if (req.path.startsWith("/api/")) {
        return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
    return res.status(500).send("Something went wrong.");
});

async function start() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS diary_users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(254) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS diary_letters (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES diary_users(id) ON DELETE CASCADE,
            title VARCHAR(120) NOT NULL DEFAULT '',
            body TEXT NOT NULL DEFAULT '',
            entry_date DATE NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);
    await pool.query(`
        CREATE INDEX IF NOT EXISTS diary_letters_user_updated_idx
        ON diary_letters (user_id, updated_at DESC)
    `);

    app.listen(port, "0.0.0.0", () => {
        console.log(`Dear Diary is listening on port ${port}.`);
    });
}

start().catch((error) => {
    console.error("Unable to start Dear Diary. Check the database configuration.", error);
    process.exitCode = 1;
});
