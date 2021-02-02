import bpak
import os

# Assuming these packages are already existing
# with transport set to bsdiff on some parts
os.system("bpak create /tmp/source.bpak");
os.system("bpak create /tmp/target.bpak");

source = bpak.Package("/tmp/source.bpak", "r");
target = bpak.Package("/tmp/target.bpak", "r");

transport = bpak.Package("/tmp/transport.bpak", "wb+");
target.transport(source, transport, rate_limit_us=0);

print(target.size());
