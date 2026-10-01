import express, { type Express, type RequestHandler } from 'express';

import { type Principal, type Role, authenticate, issue } from './auth.js';

declare global {
  namespace Express {
    interface Request {
      user?: Principal; // optional, so every handler has to remember it might be missing
    }
  }
}

const secret: string = process.env.secret ?? 's3cret';

const authenticateMiddleware =
  (secret: string): RequestHandler =>
  (req, res, next) => {
    const auth = authenticate(secret, req);
    if (typeof auth === 'string') return void res.status(401).json({ error: auth });
    req.user = auth;
    next();
  };

// Check if the user has the required role
const requireRole =
  (role: Role): RequestHandler =>
  (req, res, next) => {
    if (req.user?.roles.includes(role)) next();
    else res.status(403).json({ error: 'Forbidden' });
  };

const app = express();
app.use(authenticateMiddleware(secret));

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/login', (_req, res) => {
  res.json({ token: issue(secret, 'alice', ['user']) });
});

app.get('/orders', requireRole('user'), (_req, res) => {
  res.json({ orders: ['#1001', '#1002'] });
});

app.get('/admin/export', requireRole('admin'), (_req, res) => {
  res.json({ export: ['a@example.com', 'b@example.com'] });
});

// `requireRole` is missing, looks inconspicuous
// one mistake away from introducing a vulnerability
app.post('/admin/refund', (_req, res) => {
  res.json({ refunded: 999.99 });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`Front controller listening on http://localhost:${port}`));
