# TODO

Open tasks for bpak. Add new tasks under the matching section with enough
context to pick them up later (file, function, why). When a task is done,
move it to **Done** with the commit that resolved it.

## Bugs

- [ ] `lib/mbedtls_wrapper.c` `bpak_mbed_load_public_key`: the return value
      of `mbedtls_pk_parse_public_keyfile` is ignored and the result of
      `bpak_calloc` is not checked for NULL.
- [ ] `lib/mbedtls_wrapper.c` `bpak_mbed_verify`: always returns `BPAK_OK`
      and only reports failure through `verified`. Check whether callers rely
      on this before changing it.
- [ ] `python/python_wrapper.c` `bpak_printf`: an exception raised by the log
      callback is left set and later surfaces as a `SystemError`. Report it
      with `PyErr_WriteUnraisable` instead.
- [ ] `bpak_valid_header` does not detect parts with bad alignment, see the
      commented out assertion in `test/unit/test_misc.c` `test_part_alignment`.

## Build

- [ ] `BPAK_BUILD_PYTHON_WRAPPER` is documented in `docs/build.rst` but does
      not exist. The python wrapper is only built when `BPAK_BUILD_TESTS` is
      set.
- [ ] Add an option to build the library and tool with AddressSanitizer and
      UndefinedBehaviorSanitizer. Today only the unit test code is
      instrumented.

## Tests

- [ ] `cli.test_transport` takes ~7.5 s and dominates the test run. Consider
      pytest-xdist or splitting the scenarios into separate CTest tests.

## CI

- [ ] Upload the JUnit reports from `build/test/junit/` and show test results
      in the GitHub UI.
- [ ] Update `codecov/codecov-action` from v3, which runs on a deprecated
      Node version.
- [ ] Run the tests on Windows (MSYS2); the Windows job only builds the
      minimal library today.

## Documentation

- [ ] `.readthedocs.yml` uses the removed `python.version` key and Python 3.7.
      Read the Docs now requires `build.os` and `build.tools.python`.
- [ ] Run a full Sphinx build (`docs/build.sh`) to check the new
      development setup page and its cross references.

## Done

- [x] Replace nala and the shell script tests with cmocka and pytest (acc7903)
- [x] Fix memory leaks when loading keys in the mbedtls wrapper (143724e)
- [x] Keep a reference to the python log callback (cf95611)
- [x] Development setup guide and CLAUDE.md (a9c6dce)
