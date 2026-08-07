# CI/CD security guidelines

## Pinning external actions

Every external action referenced from `.github/workflows/` MUST be pinned to a
full 40-character commit SHA. Branches and tags are forbidden as references.

```yaml
# Correct
uses: OpenHands/extensions/plugins/qa-changes@709f230e75005851cc08ffe3b374b17498b3e2ef # main

# Wrong - a tag or branch can be repointed at new code by the upstream owner
uses: OpenHands/extensions/plugins/qa-changes@main
```

A tag is a mutable pointer. Whoever controls the upstream repository can move it
to different code at any time, and a workflow that resolves it at run time will
execute whatever it points to then — with the permissions and secrets this
repository grants the job. A commit SHA is content-addressed, so the code that
runs is the code that was reviewed.

Keep the human-readable ref in a trailing comment. It records which version was
intended, so an update is reviewable as a version change rather than an opaque
hex diff.

## Updating a pinned SHA

1. Read the upstream changelog for the release you intend to adopt.
2. Resolve the tag to its SHA: `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`
3. Update the SHA and the trailing comment together, in one commit.
4. Never update a pin by resolving a branch head without reading what changed.

## Review cadence

Review pinned actions monthly, and immediately on notice of an upstream security
release. A pin is not a substitute for patching: it makes the version explicit,
which means a stale pin stays stale until someone moves it deliberately.

## Verifying a pinned SHA

A pin is only as good as the review that placed it. Before changing one, confirm
the new SHA is reachable from the upstream tag it claims to represent:

    git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>

A SHA that no upstream ref points at is not a pin — it is an arbitrary commit,
and it may never have been reviewed by the action's maintainers. Record the tag
the SHA was resolved from in the trailing comment so the next reviewer can repeat
the check without guessing which release was intended.
