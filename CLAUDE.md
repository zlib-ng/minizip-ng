# Contribution Guidelines

These guidelines apply to changes made with coding agents.

## Code

* Prefer the smallest correct change.
* Match the naming, error handling, and idioms of the surrounding code.
* Reuse existing helpers before adding new ones or new platform APIs.
* Only add unit tests when they add enough value to the overall project.
* Verify behavior by building and running the tests.

## Writing

These rules apply to comments, documentation, commit messages, and pull request descriptions.

* Be terse, and lead with the point before the supporting detail.
* Prefer several short paragraphs over one dense block.
* Use commas to break long sentences into readable clauses.
* Write complete sentences, and don't split them with colons, semicolons, or dashes.
* Cut hedging, filler, and preambles.
* Wrap function names, macros, and other code identifiers in backticks.

## Comments

* Only comment on what the code can't show, such as surprising OS or API behavior and file format quirks.
* Wrap comments at about 100 characters.
* Describe what the code does, not what it used to do.
* Leave existing comments alone during a refactor unless they become wrong or unnecessary.

## Documentation

* Describe each function in `doc/` with one short, factual sentence.
* Drop clauses that the function name, its verb, or its symmetric sibling already imply.

## Commits

* Check formatting with clang-format before committing.
* Split logically independent changes into separate commits, ordered so each one builds on the last.
* Always prefer to amend existing commits instead of creating new ones.
* Start the title with a lowercase component prefix.
* Scope the body to the commit itself, without referencing other commits or narrating the debugging session.
* Don't put tables or trees in the body.
* End the message with an `Assisted-By:` trailer naming the agent.

## Pull Requests

* Use the same title format as commits.
* Explain the problem and the fix without hard line wraps.
* Don't add a test plan or a TL;DR.
* Close related issues with `Closes #123`.
