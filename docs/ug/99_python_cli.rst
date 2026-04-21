Python CLI
==========

The ``bpak`` command shipped by the ``bpak`` Python package (``pip install bpak``)
is an idiomatic Click application. Its command-line interface is **not** the
same as the C ``bpak`` binary documented in the preceding chapters. The C
binary is unchanged; anyone needing the historical argv should continue to
install and run it directly.

If you were using a previous version of the Python ``bpak`` script, see the
migration table below for the new shape of every subcommand.

Overview
--------

- Two-level command groups: operations on parts and metadata are written as
  ``noun verb``, e.g. ``bpak add part`` / ``bpak delete meta``.
- ``-v/--verbose`` is global on the root group: ``bpak -v add part ...`` rather
  than per-command.
- The IDs of parts and metadata are positional arguments on every command that
  addresses a single item. Where the C CLI accepted ``--part foo``, the Python
  CLI takes ``foo`` positionally.
- Commands that produce binary data (``extract part``, ``extract meta``,
  ``show hash --binary``) refuse to write to stdout when stdout is a terminal.
  Redirect to a file or pass ``--output PATH``.
- ``generate keystore --name`` validates its argument as a C identifier
  (``[A-Za-z_][A-Za-z0-9_]*``) before emitting any generated C source.

Command reference
-----------------

.. code-block:: text

    bpak [--version] [-v/--verbose...]

    Package lifecycle
      bpak create FILE [--hash {sha256|sha384|sha512}]
                       [--signature {prime256v1|secp384r1|secp521r1|rsa4096}]
                       [--force]
      bpak compare FILE1 FILE2

    Inspection
      bpak show FILE                              # full package overview
      bpak show meta FILE [ID] [--part-ref REF]
      bpak show part FILE ID [--hash]
      bpak show hash FILE [--binary]              # header hash (Package.digest)

    Content
      bpak add part   FILE ID --from PATH [--no-hash]
      bpak add meta   FILE ID (--from-string VAL | --from-file PATH)
                              [--encoder {uuid|integer|id}] [--part-ref REF]
      bpak add key    FILE ID --from PATH
      bpak add merkle FILE ID --from PATH

      bpak set meta   FILE ID VALUE [--encoder {integer|id}] [--part-ref REF]
      bpak set header FILE [--key-id ID] [--keystore-id ID]

      bpak delete part FILE (ID | --all) [--keep-meta]
      bpak delete meta FILE ID [--part-ref REF]

      bpak extract part FILE ID [--output PATH]
      bpak extract meta FILE ID [--output PATH] [--part-ref REF]

    Signing
      bpak sign   FILE (--key PATH | --signature PATH)
      bpak verify FILE (--key PATH | --keystore PATH)

    Transport
      bpak transport add    FILE ID --encoder NAME --decoder NAME
      bpak transport encode FILE --output PATH [--origin PATH]
      bpak transport decode FILE --output PATH [--origin PATH]

    Code generation
      bpak generate id STRING
      bpak generate keystore FILE --name NAME [--decorate]

Notable differences from the C CLI
----------------------------------

``show`` prints a single ``Header hash`` line in its overview output. The C
CLI's full ``bpak show`` additionally prints a ``Payload hash`` value. The
Python wrapper only exposes the header hash today; use the C ``bpak show``
binary when you need the payload hash.

``show hash`` prints the header hash. It replaces the overloaded
C-style ``-H`` / ``-B`` / ``-P`` flag combinations. For a part-level hash,
use ``bpak show part FILE ID --hash``.

``compare`` diffs part contents via ``Package.part_sha256`` on both sides
in addition to part-header fields. The previous Python CLI only compared
part *sizes*, so same-size-different-content parts were silently reported
as equal.

Migration from the previous Python CLI
--------------------------------------

+----------------------------------------------------+----------------------------------------------------------+
| Previous Python CLI                                | New Python CLI                                           |
+====================================================+==========================================================+
| ``bpak create FILE -H sha256 -S prime256v1 -Y``    | ``bpak create FILE --hash sha256 --signature prime256v1  |
|                                                    | --force``                                                |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak add FILE -p fs -f rootfs.img``              | ``bpak add part FILE fs --from rootfs.img``              |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak add FILE -m version -s 1.0.0``              | ``bpak add meta FILE version --from-string 1.0.0``       |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak add FILE -p key --encoder key -f k.pem``    | ``bpak add key FILE key --from k.pem``                   |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak add FILE -p fs --encoder merkle -f r.img``  | ``bpak add merkle FILE fs --from r.img``                 |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak show FILE``                                 | ``bpak show FILE`` (unchanged shape; overview)           |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak show FILE -m version``                      | ``bpak show meta FILE version``                          |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak show FILE -P fs``                           | ``bpak show part FILE fs --hash``                        |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak show FILE -H``                              | ``bpak show hash FILE``                                  |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak show FILE -B``                              | ``bpak show hash FILE --binary``                         |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak set FILE -m version -s 2.0.0``              | ``bpak set meta FILE version 2.0.0``                     |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak set FILE --key-id X --keystore-id Y``       | ``bpak set header FILE --key-id X --keystore-id Y``      |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak delete FILE -p fs``                         | ``bpak delete part FILE fs``                             |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak delete FILE -a``                            | ``bpak delete part FILE --all``                          |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak extract FILE -p fs -o fs.img``              | ``bpak extract part FILE fs --output fs.img``            |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak extract FILE -m version``                   | ``bpak extract meta FILE version`` (stdout, non-TTY)     |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak transport FILE --add --part fs``            | ``bpak transport add FILE fs --encoder ENC --decoder D`` |
| ``--encoder E --decoder D``                        |                                                          |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak transport FILE --encode --output o.bpak``   | ``bpak transport encode FILE --output o.bpak``           |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak transport FILE --decode --output o.bpak``   | ``bpak transport decode FILE --output o.bpak``           |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak sign FILE -k priv.pem``                     | ``bpak sign FILE --key priv.pem``                        |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak verify FILE -k pub.pem``                    | ``bpak verify FILE --key pub.pem``                       |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak verify FILE -K keystore.bpak``              | ``bpak verify FILE --keystore keystore.bpak``            |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak generate id STRING``                        | ``bpak generate id STRING`` (unchanged)                  |
+----------------------------------------------------+----------------------------------------------------------+
| ``bpak generate keystore FILE -n NAME``            | ``bpak generate keystore FILE --name NAME``              |
+----------------------------------------------------+----------------------------------------------------------+

Breaking changes (no compatibility shims)
-----------------------------------------

- All short flags that differ from the common ``-o`` / ``-v`` set are removed.
- ``-Y`` is replaced by ``--force`` on ``create``.
- ``show`` no longer overloads ``-p`` to mean "filter by part reference" when
  ``-m`` is given. Use ``--part-ref REF`` explicitly.
- ``add``, ``set``, ``delete``, and ``extract`` are split into two-level
  subgroups (``part`` / ``meta`` / ``key`` / ``merkle`` / ``header``).
- ``transport`` subcommands replace the ``--add / --encode / --decode`` mode
  flags.
