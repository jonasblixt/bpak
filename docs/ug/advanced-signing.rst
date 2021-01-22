Advanced signing example
========================

A not so un-common development flow is working on development releases that
after some iteration turn in to release candidates. The rc's pass through a
number of test steps and eventually a release candidate is considered to be
acceptable for release to production/customer.

At this point it's often desirable to not rebuild the artifacts since it would
incur another suite of testing before it can be released. To enable a flow
where release candidates can be used directly bitpacker supports re-signing.

Update key-id and keystore-id::

    $ bpak set demo.bpak --key-id "the-new-key-id" \
                         --keystore-id "some-other-keystore"

Extracting the hash in binary form::

    $ bpak show demo.bpak --hash > hash.bin

Signing the hash using openssl::

    $ cat hash.bin | openssl pkeyutl \
                          -sign -inkey prime256v1-key-pair.pem \
                          -keyform PEM > signature.bin

Overwrite the current signature with the openssl generated one::

    $ bpak sign demo.bpak --signature signature.bin

This enables a signing process with sensitive keys to be de-coupled from the
normal build environment and tools. The signing environment is usually backed
by a HSM where the sensitive keys are stored.
