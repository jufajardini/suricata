---
name: suricata-contributing
description: Use when preparing or reviewing Suricata contributions so code, docs, commits, PR workflow, tickets, and backports follow OISF rules.
---

# Suricata Contributing

Use this skill when work is meant to become a Suricata contribution, or when
you need to check whether a change is submission-ready.

## Start Here

Before writing code for a contribution:

1. Confirm there is a
   [Redmine ticket](https://redmine.openinfosecfoundation.org/projects/suricata/issues),
   unless the change is truly trivial.
2. Ensure the ticket is assigned to the contributor before substantial work.
3. For new features, ask the team first through the
   [Suricata forum](https://forum.suricata.io/c/developers/8),
   [Suricata Discord](https://discord.com/invite/t3rV2x7MrG), or the related
   Redmine ticket before implementing the feature.
4. Remind the user that OISF requires a signed
   [Contribution Agreement](https://suricata.io/contribution-agreements/) for
   external contributions.
5. Do not take on more than 3 open PRs and assigned tickets at the same time.
   Prioritize finishing in-progress work before starting new contribution work.

If the ticket is already assigned to someone else, stop and ask the user how
they want to proceed.

## Branch Rules

- Default target branch: `main`.
- Only work against stable branches such as `main-8.0.x` for approved bugfix
  backports or exceptional cases discussed with maintainers first.
- Use descriptive branch names with the ticket and revision, for example
  `geoip-feature-123-v1`.
- Each PR iteration must use a new branch and a new PR version such as `-v2`.
- Do not keep updating the same branch after opening the PR.

## Implementation Expectations

- Follow Suricata coding style and the existing patterns in the touched area.
- Keep commits logically separated.
- Do not mix unrelated fixes in one commit.
- Do not combine renames, moves, and behavior changes in the same commit.
- If behavior changes or new functionality is added, include documentation
  updates in a separate commit with the same ticket number in the message.
- Add `suricata-verify` tests whenever possible. If not possible, add unit
  tests.
- For new keywords or options, include example rules.
- For bug fixes, provide or preserve the minimal reproducer material, including
  trimmed pcaps when relevant.

If the contribution is a new non-core feature, raise the extra acceptance bar:
expect `suricata-verify` coverage, compatibility evidence for replaced features,
and a maintenance commitment from the contributor or sponsor.

## Commit Rules

Every commit should be individually buildable in sequence.

Use commit messages with:

- A meaningful subject line, 50 characters max.
- A subsystem prefix such as `stream:` or `detect:`.
- A blank line after the subject.
- A body wrapped around 72 characters.
- Relevant ticket or bug references when applicable, such as `Bug: #6240.`

Also ensure:

- Fixup commits are squashed before submission.
- Set the author identity to the contributor's actual
  `FirstName LastName <email@example.com>` and use the same email address that
  was used to sign the Contribution Agreement.
- The commit body mentions compiler warnings, Coverity findings, or static
  analysis issues when those are part of the change.

When unsure about subsystem naming or message style, inspect nearby Suricata git
history for the touched files.

## Pull Request Rules

- A PR corresponds to one branch only.
- Read the PR template and fill it in adequately.
- The PR description must be complete and link the Redmine ticket.
- If this is a new revision, link the previous PR and summarize what changed
  since the prior iteration.
- When the first PR is submitted for an issue, update the Redmine ticket status to
  `In Review`.
- If GitHub CI fails, do not treat the PR as ready. Fix the issue or close the
  PR iteration and send a new one.
- Feature-changing PRs must include a documentation update commit.
- Do not force-push unless there is no practical alternative. If a PR branch is
  force-pushed, change that PR to `draft` and leave it draft.

Use draft PRs for work that is not mergeable as-is, including PRs that were
force-pushed. State what feedback is being requested.

## Feedback Workflow

Suricata expects a new PR revision after requested changes.

When feedback arrives:

1. Create a new branch revision, such as `-v2`.
2. Apply the requested changes there.
3. Open a new PR instead of force-updating the original review branch.
4. Link the earlier PR and describe the delta clearly.
5. If an older PR was force-pushed and left in draft, close it once the newer
   PR version is open and reference the replacement PR.

## AI Usage

- Generative AI use is allowed, but it must be disclosed.
- Do not write PR titles, PR descriptions, or PR-related communication on the
  contributor's behalf.
- Any AI-generated code or commit message content must be understood by the
  contributor before submission.


## Documentation Rules

Apply these only when editing the user or developer guide:

- Use reStructuredText.
- Wrap lines at 80 characters or fewer.
- Prefer automatically generated diagrams or images when possible.
- Keep output suitable for both Read the Docs and PDF rendering.

Heading order:

- `#` for h1
- `*` for h2
- `=` for h3
- `-` for h4
- `~` for h5
- `^` for h6

For rule documentation, reuse the existing `example-rule` container and role
conventions already used in the docs.

## Backports

Only start a backport after the PR to `main` has been merged.

For backports:

1. Confirm the issue actually needs a backport.
2. Cherry-pick the relevant commits one at a time, oldest first, with
   `git cherry-pick -x`.
3. Resolve small conflicts inside the cherry-picked commit when appropriate.
4. Add follow-up commits only when needed to adapt behavior to the older
   branch.
5. Title the PR with the target branch marker, for example
   `(8.0.x-backport)`.
6. Reference the backport ticket and add the correct milestone label.

If the main-branch fix does not apply cleanly to the stable branch, implement a
version-specific fix instead of forcing a misleading cherry-pick trail.

## Submission Checklist

Before calling work submission-ready, verify:

- Ticket exists and is assigned correctly.
- Branch targets the correct base.
- Commits are clean, structured, and individually buildable.
- Tests and docs match the behavioral change.
- PR text links the ticket and explains the revision.
- Any backport work starts only after the `main` PR merged.

## Source Docs

Open these repo docs when you need the full wording or edge cases:

- `doc/userguide/devguide/contributing/contribution-process.rst`
- `doc/userguide/devguide/contributing/code-submission-process.rst`
- `doc/userguide/devguide/contributing/github-pr-workflow.rst`
- `doc/userguide/devguide/contributing/backports-guide.rst`
