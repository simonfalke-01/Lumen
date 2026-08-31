On Windows we use msys2 and ucrt64 to compile.
You need to prefix commands with `C:\msys64\msys2_shell.cmd -defterm -here -no-start -ucrt64 -c`.

Prefix build directories with `cmake-build-`.

The test executable is named `test_sunshine` and will be located inside the `tests` directory within
the build directory.

The project uses gtest as a test framework.

When adding localization do not update any language other than `en`. This also means to exclude en-US or other variants.

Always add or update doxygen documentation.

The project requires that everything be documented in doxygen or the build will fail.

Primary doxygen comments should be done like so:

```cpp
  /**
   * @brief Describe the function, structure, etc.
   *
   * @param my_param Describe the parameter.
   * @return Describe the return.
   */
```

Inline doxygen comments should use `///< ...` instead of `/**< ... */`.

Always follow the style guidelines defined in .clang-format for c/c++ code.

Do not ever create issues or pull requests.
If asked to create an issue or pull request, do so in their fork instead of the LizardByte GitHub organization.
Never create an issue or pull request in the LizardByte GitHub organization.

## Functional-First Testing and Validation

This policy applies to every remaining gate and goal in Umbra and Lumen. It must not be relaxed, bypassed, or reinterpreted without an explicit newer user instruction.

- Make the real feature work before running broad testing, auditing, review, qualification, or evidence-generation passes.
- During debugging, run only the smallest check whose result can change the immediate next action. If a check is even borderline redundant, speculative, or unable to affect the next decision, do not run it.
- Never let a broad build, monolithic test target, proof harness, validator, static-analysis suite, artifact manifest, or repeated reviewer loop block a faster direct functional test unless it is required to prevent destructive or unrecoverable harm.
- Prefer this loop: reproduce the exact live failure, identify one cause, make one bounded fix, build only the affected target, and immediately rerun the live scenario.
- Do not rerun checks that already passed unless relevant code or runtime state changed in a way that can invalidate them.
- Do not substitute tests, mocks, source inspection, manifests, or reviews for real runtime functionality.
- Defer exhaustive tests, validation, accessibility audits, performance qualification, security audits, packaging checks, artifact sealing, and independent review to their explicitly scheduled later gate or goal after the named functionality works.
- Keep only tests that directly protect a confirmed bug, safety invariant, or production contract. Remove temporary debug tests, duplicated validators, stale evidence scripts, one-off proof harnesses, and other time-wasting scaffolding once the feature works.
- Treat removal as permanent: do not add a removed test, validator, harness, audit script, or equivalent check back later under the same or a different name unless the user explicitly requests it.
- Source-freeze machinery, artifact-sealing ceremony, evidence-only manifests, and process-only validation scaffolding are presumed unwanted and must be removed before Gate 9 once Gate 8 functionality works; do not recreate them without explicit user instruction.
- Do not create tests or validation merely to satisfy process, reviewer, gate, coverage, evidence, or completion ceremony. A check must protect a concrete live behavior or safety invariant that cannot be covered more directly.
- When usefulness is borderline, presume the check is useless and skip or remove it. The burden is on the check to prove that it controls an immediate engineering decision.
- Before starting any check expected to take more than 60 seconds, state the exact hypothesis and the decision controlled by its result. If there is no concrete decision, skip the check.
- Essential rollback, data-preservation, credential-safety, and destructive-action guards remain mandatory. Keep them minimal and do not expand them into general qualification work.

Add or update tests for new or modified methods and code. Target 100% coverage on changed code.
