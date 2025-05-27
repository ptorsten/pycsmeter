# Contributing to pycsmeter

We love your input! We want to make contributing to pycsmeter as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with Github
We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [Github Flow](https://guides.github.com/introduction/flow/index.html)
Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License
In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE.md) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issue tracker](https://github.com/ptorsten/pycsmeter/issues)
We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/ptorsten/pycsmeter/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## License
By contributing, you agree that your contributions will be licensed under its MIT License.

## Environment setup

Nothing easier!

Fork and clone the repository, then:

```bash
cd pycsmeter
make setup
```

> NOTE: If it fails for some reason, you'll need to install [uv](https://github.com/astral-sh/uv) manually.
>
> You can install it with:
>
> ```bash
> curl -LsSf https://astral.sh/uv/install.sh | sh
> ```
>
> Now you can try running `make setup` again, or simply `uv sync`.

You now have the dependencies installed.

You can run the application with `make run pycsmeter [ARGS...]`.

Run `make help` to see all the available actions!

## Tasks

The entry-point to run commands and tasks is the `make` Python script, located in the `scripts` directory. Try running `make` to show the available commands and tasks. The *commands* do not need the Python dependencies to be installed,
while the *tasks* do. The cross-platform tasks are written in Python, thanks to [duty](https://github.com/pawamoy/duty).

If you work in VSCode, we provide [an action to configure VSCode](https://pawamoy.github.io/copier-uv/work/#vscode-setup) for the project.

## Development

As usual:

1. create a new branch: `git switch -c feature-or-bugfix-name`
1. edit the code and/or the documentation

**Before committing:**

1. run `./scripts/make format` to auto-format the code
1. run `./scripts/make check` to check everything (fix any warning)
1. run `./scripts/make test` to run the tests (fix any issue)
1. if you updated the documentation or the project dependencies:
    1. run `./scripts/make docs`
    1. go to http://localhost:8000 and check that everything looks good
1. follow our [commit message convention](#commit-message-convention)

If you are unsure about how to fix or ignore a warning, just let the continuous integration fail, and we will help you during review.

Don't bother updating the changelog, we will take care of this.

## Commit message convention

Commit messages must follow our convention based on the [Angular style](https://gist.github.com/stephenparish/9941e89d80e2bc58a153#format-of-the-commit-message) or the [Karma convention](https://karma-runner.github.io/4.0/dev/git-commit-msg.html):

```
<type>[(scope)]: Subject

[Body]
```

**Subject and body must be valid Markdown.** Subject must have proper casing (uppercase for first letter if it makes sense), but no dot at the end, and no punctuation in general.

Scope and body are optional. Type can be:

- `build`: About packaging, building wheels, etc.
- `chore`: About packaging or repo/files management.
- `ci`: About Continuous Integration.
- `deps`: Dependencies update.
- `docs`: About documentation.
- `feat`: New feature.
- `fix`: Bug fix.
- `perf`: About performance.
- `refactor`: Changes that are not features or bug fixes.
- `style`: A change in code style/format.
- `tests`: About tests.

If you write a body, please add trailers at the end (for example issues and PR references, or co-authors), without relying on GitHub's flavored Markdown:

```
Body.

Issue #10: https://github.com/namespace/project/issues/10
Related to PR namespace/other-project#15: https://github.com/namespace/other-project/pull/15
```

These "trailers" must appear at the end of the body, without any blank lines between them. The trailer title can contain any character except colons `:`. We expect a full URI for each trailer, not just GitHub autolinks (for example, full GitHub URLs for commits and issues, not the hash or the #issue-number).

We do not enforce a line length on commit messages summary and body, but please avoid very long summaries, and very long lines in the body, unless they are part of code blocks that must not be wrapped.

## Pull requests guidelines

Link to any related issue in the Pull Request message.

During the review, we recommend using fixups:

```bash
# SHA is the SHA of the commit you want to fix
git commit --fixup=SHA
```

Once all the changes are approved, you can squash your commits:

```bash
git rebase -i --autosquash main
```

And force-push:

```bash
git push -f
```

If this seems all too complicated, you can push or force-push each new commit, and we will squash them ourselves if needed, before merging.
