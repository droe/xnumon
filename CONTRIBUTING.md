# Contributing Guidelines

Contributions are very welcome and acknowledged in the
[Authors](https://github.com/droe/xnumon/blob/develop/AUTHORS.md)
file!

-   Submit pull requests solving bugs,
    [open issues](https://github.com/droe/xnumon/issues)
    or improving the documentation.
-   Discuss your contribution in an existing or new issue ticket beforehand to
    see if the maintainer is interested in merging it.

By contributing, you agree to the terms of the
[Contributor Agreement](https://github.com/droe/xnumon/blob/develop/LICENSE.contrib).
If you contribute very significant code for which the terms of the Contributor
Agreement may be unsuitable, contact the maintainer.

## Branching Model

Development happens in the `develop` branch, releases are fast-forward-merged
to `master` and tagged with the version.

When contributing code, please:

-   Fork the repository into your namespace.
-   Create a feature branch off `develop` for each logically separate
    contribution.
-   Commit your changes against your feature branch.
-   Test your changes in different relevant configurations.
-   Submit a pull request against `develop`.
-   If continuous integration fails or a maintainer requests changes, push
    additional commits remedying the situation to your feature branch.

Avoid submitting pull requests directly from your copy of `master` or `develop`
because that is prone to polluting pull requests when you later commit more
changes to your fork.
