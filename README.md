# Have AI agents killed secure coding?

Demo code for the talk *Have AI Agents Killed Secure Coding?*.

The talk argues that "make it secure" is not a checkable instruction, for an agent or a human.
Security design patterns help because they turn a vague principle into a property you can check.

This repository shows an example of how the principle of *complete mediation* (every request is checked for authority) can be made measurable with two patterns from Yoder and Barcalow:

- **Single Access Point:** every route is registered through one `route()` method.
- **Check Point:** one function, `checkPoint()`, checks the caller's role and returns proof that the check happened.

A handler can only be called with that proof.
A missing or wrong role is a compile error, introducing vulnerabilities becomes more difficult.

## Repository layout

| File | Purpose |
| :--- | :--- |
| [`basic/src/auth.ts`](basic/src/auth.ts) | Shared roles, JWT authentication, and `checkPoint()`. |
| [`basic/src/basic-express.ts`](basic/src/basic-express.ts) | The usual Express way: `requireRole` middleware per route. `/admin/refund` forgets it and is open to anyone. |
| [`basic/src/front-controller.ts`](basic/src/front-controller.ts) | The same API behind a `FrontController`. Forgetting the role does not compile. |

## Try it

Install dependencies:

```bash
bun install
```

Type-check the code:

```bash
bun run types:basic
```

To see the guarantee, uncomment one of the two `app.route(...)` lines at the end of the route list in `front-controller.ts` and type-check again. Both fail to compile.

Start the front controller on port 3000 (set `PORT` to change it):

```bash
secret=change-me bun run serve
```

## Limitations

The demo only checks roles (vertical authorization). It does not check that a user can only access their own data (horizontal authorization).
