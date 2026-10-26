# Verified Runs

Agents running real jobs in Tracekit Box, each with its signed record. CI runs `tracekit verify` on every run, and the
numbers below are counted from the records that verified, not taken from what anyone wrote. A run that does not verify
is not listed.

<!-- BEGIN table: written by `make runs` from the verified records; do not edit by hand -->
| Agent | Task | Commands | Connections | Held | Refused | Integrity |
|---|---|--:|--:|--:|--:|---|
| [By hand \(tkbox exec\)](by-hand/readme-demo/) | The README demo: install curl and requests, then try each way out of the box: a host off the allowlist, the cloud metadata address, and a GitHub token bound to api.github.com. | 7 | 39 | 1 | 2 | VERIFIED |
<!-- END table -->

## The columns

- **Agent**, **Task**: from the run's `run.yaml`, in the contributor's words.
- **Commands**: the commands the box ran, each a `Bash` call the signer decided.
- **Connections**: the connections that got as far as the signer, each a `WebFetch` call it decided. A connection Box
  refuses before asking, such as one to the cloud metadata address, is counted under Refused only.
- **Held**: calls held for a person: hosts off the allowlist waiting for `tkbox approve`, and calls the signer's policy
  held for approval.
- **Refused**: the signer's refusals and its holds that never ran, the connections Box refused itself, and secrets
  stopped on their way to the wrong host. A host held for a person that no one approved ends refused, so it counts in
  both columns.
- **Integrity**: what `tracekit verify` printed.

A run that verifies proves that its record is intact and was signed by the signer its trust file pins. A contributor's
run usually comes from a dev signer (`Assurance: dev`): it shows that no one changed the record after it was signed,
not whose machine ran it. See [Verify a bundle](../README.md#verify-a-bundle).

## Add a run

One PR per run; every new agent family is worth one.

1. Run your agent in Box on a small real task (see the [Quick look](../README.md#quick-look)), allowing only the hosts
   it needs.
2. Stop the box and export its record:

   ```sh
   tkbox stop JOB
   tkbox export JOB -o run.tkb                      # writes run.tkb and run.trust.json
   tracekit verify run.tkb --trust run.trust.json   # Integrity: VERIFIED.
   ```

3. Make a folder `runs/<agent>/<short-name>/` (lowercase letters, digits, `.`, `_` and `-`), such as
   `runs/claude-code/fix-flaky-test/`, holding these three files and nothing else:
   - `run.tkb` and `run.trust.json`, as `tkbox export` wrote them;
   - `run.yaml`, your account of the run:

     ```yaml
     agent: Claude Code          # the agent's name
     agent_version: "1.2.3"      # its version
     image: python:3.12-slim     # tkbox run --image
     allow: [pypi, anthropic]    # the tkbox run --allow entries, or [] for none
     task: >                     # the task in a sentence or two
       Fix the flaky test in tests/test_io.py.
     notes: >                    # what you saw: held calls, refusals, anything that broke
       pip reached PyPI on the allowlist; one call to an analytics host was held and no one approved it.
     ```

4. Run `make runs` (it needs Go and `pip install tracekit-ai==1.4.2`). It verifies every run and rewrites the table
   above; commit the README with your run.
5. Open the PR. CI runs the same check and fails on a run that does not verify or a table that is out of date.

Box records only placeholders for secrets, so no secret value is in the bundle. Everything in the folder is public once
merged, so read your `run.yaml` before you commit it.
