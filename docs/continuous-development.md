# Continuous Development

AEGIS OS now includes a baseline continuous development stack inside the repository:

## What Runs Automatically

- `AEGIS CI`
  - runs on every push to `main`
  - runs on every pull request targeting `main`
  - checks formatting, linting, tests, and release builds
  - builds and smoke-tests the Docker image

- `AEGIS Maintenance`
  - runs every 6 hours
  - re-checks repository health even when no one is actively pushing code
  - uploads a maintenance report as a workflow artifact
  - opens or updates a GitHub issue automatically when a scheduled run fails

- `Dependabot`
  - keeps Cargo, GitHub Actions, and Docker dependencies moving forward weekly

## What This Enables

- faster feedback on regressions
- repeated validation without waiting for a contributor to remember to run tests
- visible maintenance alerts in GitHub Issues when the project health drops
- safer ongoing modernization of dependencies

## What It Does Not Do Yet

This repository setup provides continuous validation and maintenance reporting. It does not, by itself, write new product code or auto-merge fixes.

To get true autonomous code changes, pair this repository setup with:

1. a coding agent or automation service that can clone the repo, edit code, run tests, and open pull requests
2. repository credentials or app installation with scoped permissions
3. branch protections and PR review rules

## Recommended Next Setup

1. Install Rust locally anywhere maintainers work on the repo.
2. Enable required status checks for `AEGIS CI`.
3. Keep the external Codex automation active for hourly improvement passes.
