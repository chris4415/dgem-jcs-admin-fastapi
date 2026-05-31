# DG-E&M ChatGPT Feedback Copy v001

## Purpose

Add a persistent bottom workbench to every JCS-admin page so the user can send clean text feedback to ChatGPT without repeated screenshots.

## Features

- Copy for ChatGPT button
- Show Packet button
- AI Assistance text box
- Governed API Console text box
- Page-aware feedback packet
- Clipboard copy where browser permits
- Fallback visible text packet where clipboard copy is blocked

## Boundary

The webpage can copy text to the clipboard and fill its own local text boxes.

It cannot reliably paste directly into the external ChatGPT composer because browsers isolate pages from other sites.

## Governing Rule

This feature is a feedback and support mechanism only.

It does not execute actions, run scripts, modify files, query DuckDB, or bypass the governed runner.
