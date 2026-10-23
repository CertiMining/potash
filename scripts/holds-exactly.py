#!/usr/bin/env python3
"""Does a dumped ProgramData account hold exactly this artefact, and nothing after it?

Exit 0 when it does, which `scripts/upgrade-devnet.sh` reads as "no upgrade to perform".

**Why by bytes and not by length.** `solana program show` reports `Data Length`, which is the
account's capacity less its 45-byte header, and the loader keeps no record of how much of that the
ELF occupies: it writes the program and zero-pads the rest. Before the announced deployment's first
extend the capacity and the program length coincided, because the account had been allocated to fit
exactly. After the extend of 22 October they differ by 8,096 bytes, and a guard comparing them would
have stopped firing without saying so.

**What this cannot see, established by probing it rather than by reasoning.** The artefact ends with
15 zero bytes, so an artefact truncated anywhere inside its own trailing zeros produces a dump whose
tail is still all zeros, and this reports "holds exactly" for it. Those bytes are not recoverable from
the chain at all: the account is zero-padded and carries no length. A probe of a one-byte-short
artefact returned 0 where 1 was expected, which is how this paragraph came to be written.

For this guard's purpose the blind spot is harmless — deploying a zero-truncated copy of what is
already deployed writes the same bytes — but it is a blind spot, and it would be the wrong primitive
for answering "is the deployed program exactly this file".
"""

import pathlib
import sys


def holds_exactly(deployed: bytes, artefact: bytes) -> bool:
    """The deployed bytes begin with the artefact and continue with nothing but zeros."""
    if len(deployed) < len(artefact):
        return False
    if deployed[: len(artefact)] != artefact:
        return False
    return not any(deployed[len(artefact) :])


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: holds-exactly.py <dumped account> <artefact>", file=sys.stderr)
        return 2
    deployed = pathlib.Path(sys.argv[1]).read_bytes()
    artefact = pathlib.Path(sys.argv[2]).read_bytes()
    return 0 if holds_exactly(deployed, artefact) else 1


if __name__ == "__main__":
    sys.exit(main())
