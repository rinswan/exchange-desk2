# Exchange Desk (multiuser web app)

Node.js + Express + SQLite. Login, roles and all data live on the server, so every user sees the same data.

## Run it
```
npm install
cp .env.example .env      # edit as needed
npm start                 # http://localhost:3000
```
The first account created (Sign up tab, or ADMIN_ID / ADMIN_EMAIL / ADMIN_PASSWORD in .env) becomes the Super Admin.
After that, sign-up is closed unless ALLOW_SIGNUP=true; the Super Admin adds people on the Accounts page.

## Deploy
- Docker: `docker build -t exchange-desk . && docker run -p 3000:3000 -v desk-data:/data -e COOKIE_SECURE=true exchange-desk`
- Put it behind HTTPS (Caddy, nginx, Render, Railway, Fly) and set COOKIE_SECURE=true, plus TRUST_PROXY=true behind a proxy.
- Back up the DATA_DIR folder (desk.db holds everything, including uploaded files).

## What changed from the single file
- Passwords are hashed with bcrypt on the server (minimum 8 characters); sessions use an HttpOnly cookie.
- Roles and account changes are checked on the server. 3PL groups can only read and write their own data.
- Entries are shared. Two people editing at once are merged by record, and the page refreshes every few seconds.
- Tickets, replies and attachments are stored in the database. AI assistant works if ANTHROPIC_API_KEY is set.
- Removed: demo accounts, email-only password reset (ask the Super Admin), Google Sheet storage.

## Known limits
- Page-level access (the Access checkboxes) hides pages in the interface; the server only enforces who can reach staff vs each 3PL group's data.
- Rows without an id that two people edit in the same moment can still overwrite each other.
