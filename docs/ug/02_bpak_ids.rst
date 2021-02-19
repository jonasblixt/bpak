ID's
====

BPAK ID's are used to refer to meta data, parts key id's etc. Bit packer id's
are typically expressed as strings but internally they are converted to an uint32_t
using a crc32 function.

Most arguments support both inputing a string which will be translated using crc32
or a string that starts with '0x' and bypasses the crc32 function.

Invoking the built in id generator::

    $ bpak generate id some-test-string
    id("some-test-string") = 0x576a08d5
