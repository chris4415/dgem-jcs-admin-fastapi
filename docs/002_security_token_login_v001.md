# DG-E&M JCS-admin Security and Token Login v001

## Purpose

Define the initial security model for the DG-E&M JCS-admin FastAPI build.

The web system must not become an unmanaged script launcher. Every future governed action must have an authenticated actor, role, permission, request ID, audit record, and execution boundary.

## Initial security goals

1. Provide a login mechanism for the JCS-admin web interface.
2. Establish user identity for all protected routes.
3. Define simple roles before adding ChatGPT API or runner actions.
4. Prevent unauthenticated access to administrative pages.
5. Prepare for future action permissions and runner approval controls.
6. Avoid storing API keys or secrets in Git.

## Initial roles

- admin
- operator
- reviewer
- readonly
- service

## Initial implementation

For v001, use a simple local username/password configuration from environment variables.

This is acceptable for the lab foundation but must later be replaced or hardened before broader use.

## Initial admin credentials

Credentials must be supplied through environment variables, not committed to Git.

Required variables:

- DGEM_ADMIN_USER
- DGEM_ADMIN_PASSWORD
- DGEM_SESSION_SECRET

## Protected routes

The following routes require login:

- /dashboard
- /security/whoami
- future discovery pages
- future runner/action pages
- future API-control pages

## Public routes

The following routes remain public during foundation testing:

- /
- /health
- /environment
- /login

## Security boundary rule

The website may request governed actions only after authentication.

The API/control layer must validate the actor, role, action registry entry, lifecycle stage, and execution policy before any runner action is allowed.

## Future hardening

Future versions should consider:

- hashed password store
- multi-user database
- role/permission registry
- session expiry controls
- CSRF protection for forms
- HTTPS through Caddy
- audit log for login/logout
- integration with external identity provider if required
