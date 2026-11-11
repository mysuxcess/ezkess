EZKESS site (server connected)
index.html     landing page with two buttons
customer.html  customer platform (no login; each customer sees only their own request)
admin.html     lender platform (password login, then all requests, IDs, vault, settings)
solo-test.html both roles in one page, browser-only, no server (the earlier version)
functions/api/[[path]].js   the server (Cloudflare Pages Function)
_headers       noindex + basic security headers

SETUP (Cloudflare Pages)
1. Deploy this folder to Cloudflare Pages (Git or direct upload; functions/ must be included).
2. Workers & Pages > Storage > KV: create a namespace, e.g. ezkess.
3. Your Pages project > Settings > Bindings: add a KV binding named EZ pointing to that namespace.
4. Settings > Variables and Secrets (Production), add two secrets:
   ADMIN_PASSWORD  the lender login password
   SESSION_SECRET  a long random string (40+ characters)
5. Redeploy. Open admin.html, sign in, set the admin WhatsApp number on the requests page.

WHAT THE SERVER DOES
- Login: password checked on the server, 8-hour HttpOnly cookie, 8 wrong tries locks that address for 10 minutes.
- Private WhatsApp links: the wa.me message links to customers and to second-ID holders are built only on the lender page, from data only a signed-in lender can read. The customer page never receives those numbers or the lender's notes.
- Customer access: each request gets a long random key kept in that customer's browser. It opens only their own request and their own files.
- Lender and customer can each write only their own steps; the server rejects the rest.
- ID pictures and voice notes are stored in KV and readable only by the lender or the owning customer.
- Pages refresh from the server every 6 seconds, so a step sent on one device shows on the other.
Do not enter real customers' IDs until you have reviewed data-protection requirements.
