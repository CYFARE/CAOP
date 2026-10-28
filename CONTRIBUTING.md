# Contributing to CAOP

Thanks for helping improve **CYFARE's Android Optimizer Plus**! Bug reports, compatibility results, documentation fixes, and focused pull requests are all welcome.

## Report a bug

Use the [bug report template](https://github.com/CYFARE/CAOP/issues/new?template=bug_report.yml) and include:

- the command you ran and what you expected;
- your Android version, device/ROM, and Python version;
- relevant output with device serials, account details, and API keys removed;
- whether the issue also occurs with `--dry-run`.

Never post rollback journals, transcripts, or logs without reviewing them for private data.

## Make a change

1. Fork the repository and create a focused branch.
2. Keep the CLI compatible with Python 3.8+ and the standard library.
3. Add or update unit tests for behavior changes.
4. Run the full test suite:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

5. Update the README or [user guide](docs/USER_GUIDE.md) when usage changes.
6. Open a pull request explaining the change, its risks, and how you tested it.

## Safety requirements

CAOP changes real devices. New actions must preserve these guardrails:

- no app uninstalls, app-data clears, factory resets, or arbitrary shell execution;
- no unreviewed package wildcards or changes to critical/communication apps;
- validate inputs and verify device-side results rather than trusting exit codes;
- record supported reversible changes in a rollback journal;
- require explicit opt-in for risky, user-app, or root-only operations;
- redact API keys and other secrets from reports and transcripts.

Device-dependent changes should fail closed and degrade gracefully on unsupported ROMs.
