.. _Development setup:

Development setup
=================

Prerequisites
-------------

On Debian or Ubuntu everything that is needed to build bpak and run the tests
can be installed with::

    $ sudo apt install build-essential cmake pkg-config \
          libmbedtls-dev liblzma-dev uuid-dev \
          libcmocka-dev python3-dev python3-pytest openssl lcov

Other distributions provide the same libraries under similar names: mbedtls,
liblzma, libuuid, cmocka and the python3 development headers.

pytest can also be installed from PyPI into a virtual environment. CMake picks
up the active virtual environment, so activate it before configuring::

    $ python3 -m venv .venv && . .venv/bin/activate
    $ pip install -r test/requirements.txt

Building
--------

Configure a build directory with the tests enabled and build it::

    $ cmake -B build -DBPAK_BUILD_TESTS=1
    $ cmake --build build -j$(nproc)

``BPAK_BUILD_TESTS`` also builds the python wrapper and compiles the library
with coverage instrumentation. The C unit tests are built with
AddressSanitizer, which includes leak detection.

Running tests
-------------

Run the complete test suite::

    $ ctest --test-dir build --output-on-failure -j$(nproc)

Every C unit test binary and every pytest file is a separate CTest test. The
tests are labeled by group, use ``ctest -L <label>`` to run one group:

===========  ===================================================  ================
Label        Description                                          Location
===========  ===================================================  ================
unit         C unit tests of the library (cmocka)                 test/unit
cli          Tests of the bpak tool (pytest)                      test/cli
python       Tests of the python wrapper (pytest)                 test/python
===========  ===================================================  ================

The pytest based tests can be run directly against a build directory, which
gives access to all pytest options::

    $ pytest test --bpak-build-dir build
    $ pytest test --bpak-build-dir build -k transport -v
    $ pytest test/cli/test_sign.py --bpak-build-dir build -x

Setting the environment variable ``BPAK_BUILD_DIR`` replaces
``--bpak-build-dir``.

A C unit test binary can be run on its own to see the result of every test
case::

    $ ./build/test/unit/test_merkle

When the tests are run through CTest the files created by each pytest test are
kept in ``build/test/pytest/<test name>/`` and JUnit reports are written to
``build/test/junit/``.

Writing tests
-------------

Test data such as keys and reference files lives in ``test/data``.

C unit tests
~~~~~~~~~~~~

Unit tests use `cmocka <https://cmocka.org>`_ and are linked against the static
library, so internal symbols are available. A test file defines its tests as
``static void test_name(void **state)`` functions and runs them from ``main``::

    #include "test_helpers.h"

    static void test_something(void **state)
    {
        (void)state;
        assert_int_equal(bpak_valid_header(&h), BPAK_OK);
    }

    int main(void)
    {
        const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_something),
        };

        return cmocka_run_group_tests(tests, NULL, NULL);
    }

``TEST_DATA("file")`` expands to the path of a file in ``test/data`` and
``test_load_file()`` reads a whole file into memory. New test files must be
added to ``UNIT_TESTS`` in ``test/unit/CMakeLists.txt``.

Tool and python wrapper tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These tests use `pytest <https://pytest.org>`_. Every test runs in its own
temporary directory. Shared helpers are found in ``test/bpaktest.py`` and
fixtures in ``test/conftest.py``:

``bpak``
    Runs the bpak tool. ``bpak("show", pkg)`` runs a command with ``-vvv``
    and fails the test if it returns an error. Verbose logs are written to
    stdout, so use ``bpak.output(...)`` to run a command without them and get
    its output. ``bpak.fails(..., error=BpakError.VERIFY_FAIL)`` expects a
    command to fail with a specific error. ``bpak.create_package(...)``
    creates and signs a package with optional parts and transport rules.

``make_data``
    Creates a file with a given number of KiB of test data.

``pybpak``
    The python wrapper module from the build directory (``test/python``
    only). The ``origin_pkg`` and ``target_pkg`` fixtures provide signed
    packages to test against.

Parametrize tests that only differ in their input instead of duplicating them.
New test files must be added to ``PYTEST_FILES`` in ``test/CMakeLists.txt``.

Coverage
--------

Builds with ``BPAK_BUILD_TESTS`` produce coverage data when the tests are run.
Create a HTML report with lcov::

    $ lcov --directory build --capture --output-file coverage.info
    $ genhtml coverage.info --output-directory coverage_report

Code style
----------

C code is formatted with clang-format using the ``.clang-format`` file in the
repository root. Only format the code you change.

Commit messages
---------------

The first line of a commit message is prefixed with the area that the commit
changes, followed by a short summary::

    lib/verify: Compare the entire root hash not just the first byte
    test: Replace nala and shell scripts with cmocka and pytest
    docs: Describe how to run the tests

Bug fixes are additionally prefixed with ``bugfix:``::

    bugfix: lib/mbedtls: Fix memory leaks when loading keys

Keep bug fixes in separate commits from other changes.

Versioning
----------

``version.txt`` in the repository root holds the project version on the form
``MAJOR.MINOR.PATCH`` and is the only place where it is defined. It is used
for:

- the CMake project version, the shared library version and the pkg-config
  file
- ``bpak/version.h`` (``BPAK_VERSION_MAJOR``, ``BPAK_VERSION_STRING``, ...),
  which is generated into the build directory
- the python package version in ``python/setup.py``
- the Sphinx and Doxygen documentation

Builds that do not use CMake (``BPAK_HAVE_USER_SETTINGS``) must provide their
own ``bpak/version.h``, see ``lib/version.h.in``.

To make a release, update ``version.txt``, commit it as ``Version X.Y.Z`` and
tag the commit ``vX.Y.Z``.

Documentation
-------------

The documentation is built with Sphinx and Doxygen. ``docs/build.sh`` builds it
in a docker container, the output is written to ``docs/_build/html``.
