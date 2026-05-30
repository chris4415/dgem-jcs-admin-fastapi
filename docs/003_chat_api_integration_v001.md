# DG-E&M ChatGPT API Integration v001

## Purpose

Add bounded ChatGPT API integration to the JCS-admin FastAPI build after login/security exists.

The API must support DG-E&M governance principles:

- AI is not the source of truth.
- The API may reason, summarise, and propose structured actions.
- The API must not directly execute scripts.
- The API must not directly write arbitrary files.
- All future tool/action requests must pass through the governed runner boundary.
- API keys must never be committed to Git.

## Initial implementation goals

1. Store OpenAI API key in `.env` only.
2. Add OpenAI Python SDK to the web container.
3. Add a protected `/api/chat/test` route.
4. Require login before the route can be used.
5. Use a bounded fixed test prompt.
6. Return a simple API response to the authenticated user.
7. Confirm the API key is not exposed in templates, browser source, Git, or logs.
8. Prepare for future tool-call and audit logging work.

## Environment variables

Required:

- OPENAI_API_KEY

Optional:

- OPENAI_MODEL

Default model may be configured in `.env`.

## Protected route

Initial protected route:

- `/api/chat/test`

This route must require an authenticated session.

## Boundary rule

The ChatGPT API integration may return reasoning and explanation.

It must not:

- execute scripts
- choose filesystem paths
- write server files directly
- bypass the runner
- bypass the action registry
- bypass authentication
- expose secrets

## Future versions

Future versions should add:

- API audit log
- bounded context packet builder
- structured JSON output
- tool-call request schema
- runner action validation
- token/cost tracking
- timeout and retry policy
- model registry
