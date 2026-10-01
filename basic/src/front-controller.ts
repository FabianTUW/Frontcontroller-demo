// ┌──────────────────────────────────────────────────────────────────────────┐
// │ AUTHENTICATION: the Front Controller way                                 │
// │ One door. Registering a route means naming the role it requires, and a   │
// │ handler can only be called with proof that that role was checked.       │
// └──────────────────────────────────────────────────────────────────────────┘

import express, { type Express, type Response } from 'express';

import {
  type HasRole,
  type Principal,
  type Role,
  authenticate,
  checkPoint,
  issue,
} from './auth.js';

const secret: string = process.env.secret ?? 's3cret';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** MustDeclareProof types ensures that:
 * 1. its a function
 * 2. the function signature contains H
 */
type MustDeclareProof<H extends (...a: never[]) => unknown> =
  Parameters<H> extends [] ? { 'a handler must declare its HasRole<R> parameter': never } : unknown;


/** A handler can only be called with proof of its role, and can only return JSON. */
type Handler<R extends Role, H extends (...a: never[]) => unknown> = ((proof: HasRole<R>) => Json) & H & MustDeclareProof<H>;

class FrontController {
  #app = express();

  constructor(private secret: string) {}

  route<R extends Role, H extends (...a: never[]) => unknown>(
    m: 'get' | 'post',
    path: string,
    role: R,
    handler: Handler<R, H>,
  ): void {
    this.#app[m](path, (req, res: Response<Json>) => {
      const principal: Principal | string = authenticate(this.secret, req);
      if (typeof principal === 'string') {
        return void res.status(401).json({ error: 'Invalid token' });
      }

      // only checkPoint can generate this proof
      const proof: HasRole<R> | null = checkPoint(principal, role);
      if (!proof) return void res.status(403).json({ error: 'Forbidden' });

      res.json(handler(proof));
    });
  }

  listen(port: Number): void {
    this.#app.listen(port, () => console.log(`Front controller listening on http://localhost:${port}`));
  }
}

const health = (_: HasRole<'anyone'>) => ({ ok: true });
const login = (secret: string) => (_: HasRole<'anyone'>) => ({
  token: issue(secret, 'alice', ['user']),
});
const orders = (_: HasRole<'user'>) => ({ orders: ['#1001', '#1002'] });
const adminExport = (_: HasRole<'admin'>) => ({ export: ['a@example.com', 'b@example.com'] });
const adminRefund = (_: HasRole<'admin'>) => ({ refunded: 999.99 });

const app = new FrontController(secret);
app.route('get', '/health', 'anyone', health);
app.route('post', '/login', 'anyone', login(secret));
app.route('get', '/orders', 'user', orders);
app.route('get', '/admin/export', 'admin', adminExport);
app.route('post', '/admin/refund', 'admin', adminRefund);
// Neither of these compiles. asserted by the compiler.
// app.route('post', '/admin/refund', 'anyone', adminRefund);   // wrong role
// app.route('post', '/admin/refund', 'admin', () => ({ ok: 1 })); // handler declares no role

const port = Number(process.env.PORT ?? 3000);
app.listen(port);
