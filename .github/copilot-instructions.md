# Repository Instructions

This repository uses Skill-first terminal workflows.

## Preferred execution model

- Do not use wrapper scripts; execute tools directly in terminal.
- Prefer direct terminal execution of binaries in `.\redteam-tools`.
- Load and follow the `redteam` skill before launching red-team commands.

## Terminal execution contract

- Execute commands directly in terminal and read output from terminal/files.
- For long or noisy scans, redirect output to files first, then extract key lines.
- Prefer non-interactive arguments so commands can complete unattended.
- For long-running listeners, run in background mode and check output incrementally.

## Tool location

- Primary directory: `.\redteam-tools`
- Use absolute paths when command resolution fails.

## Output discipline

- For long scan output, write results to files first.
- Summarize high-signal findings only: hosts, ports, services, vulnerabilities, creds.

## Safety and reliability

- Use non-interactive command forms.
- If arguments are uncertain, read local help files in `.\redteam-tools\*_help.txt` before retrying.

