# Project State

## Current State

- Apple Notes database reads bind untrusted leaves with no-follow, nonblocking opens before regular-file and identity validation.
- File and directory publication use a monotonic commit latch before post-rename evidence work.
- Write-producing CLI commands support an inherited supervisor FD protocol for identity-bound directory creation.
- Structured, malformed, unstructured, and transport-evidence-construction creator failures retain conservative recovery evidence and close every owned or received FD.
- Per-workstream implementation and validation records live under `docs/project_journal/`.

## Recovery Pointers

- Current hardening workstream: `docs/project_journal/2026/07/2026-07-24-apple-notes-publication-creator-hardening-andb001.md`

## Global Blockers

- None.
