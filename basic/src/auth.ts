// Shared by both versions: who is calling, and may they.

import type { Request } from 'express';
import jwt from 'jsonwebtoken';

export type Role = 'anyone' | 'user' | 'admin';

export type Principal = { subject: string; roles: Role[] };

/** A Principal, or the reason the credential was rejected. */
export type Auth = Principal | string;

export function authenticate(secret: string, req: Request): Auth {
  const header = req.headers.authorization;
  if (!header) {
    // no credentials means anonymous user
    return { subject: 'anonymous', roles: ['anyone'] };
  }

  try {
    // look inside the JWT and return the principal
    const claims = jwt.verify(header.replace(/^Bearer /, ''), secret, {
      algorithms: ['HS256'],
    }) as jwt.JwtPayload;
    const claimed: string[] = Array.isArray(claims.roles) ? claims.roles : [];
    return { subject: String(claims.sub), roles: ['anyone', ...claimed.filter(isRole)] };
  } catch (e) {
    return (e as Error).message;
  }
}

export function issue(secret: string, subject: string, roles: Role[]): string {
  return jwt.sign({ roles }, secret, { subject, algorithm: 'HS256', expiresIn: '1h' });
}

const isRole = (r: string): r is Role => r === 'user' || r === 'admin';

/// CheckPoint Pattern

/** Proof that a Principal was checked for role R. Only checkPoint() can produce one. */
declare const proof: unique symbol;
export type HasRole<R extends Role> = { readonly [proof]: R; readonly role: R };

export function checkPoint<R extends Role>(user: Principal, role: R): HasRole<R> | null {
  return user.roles.includes(role) ? ({ role } as HasRole<R>) : null;
}
