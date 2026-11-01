"""
Sign a release for the updater (src/updater.py).

    python tools/sign_release.py keygen PRIVATE_KEY_FILE
        Make a key pair. The private key goes to the file, which must not exist
        yet and must stay out of the repository; the public key is printed, for
        PUBLIC_KEY in src/updater.py. The file's one line is what the
        NETSENTINEL_SIGNING_KEY secret of the GitHub repository holds.

    python tools/sign_release.py sign EXE [--tag vX.Y.Z]
        Write EXE.sig: the version (src/__init__.py) and the exe's SHA-256,
        signed with the key in the NETSENTINEL_SIGNING_KEY environment variable.
        With --tag, the tag has to be that version. The signature is checked
        against src/updater.py's PUBLIC_KEY before anything is written, so a key
        that does not match it fails here, not on every user's machine.

    python tools/sign_release.py verify EXE
        Check EXE.sig against EXE and PUBLIC_KEY.

The private key is never printed.
"""

import argparse
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import __version__  # noqa: E402
from src.updater import (UpdateError, _sha256_file, sign_manifest,  # noqa: E402
                         verify_manifest)

KEY_VARIABLE = 'NETSENTINEL_SIGNING_KEY'


def keygen(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    # O_EXCL: never overwrite a key that may already sign releases.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(base64.b64encode(raw).decode('ascii') + '\n')
    print(base64.b64encode(public).decode('ascii'))


def sign(exe, tag=None, public_key=None):
    version = __version__
    if tag is not None and tag != f'v{version}':
        raise SystemExit(f"The tag {tag} is not v{version}, the version in src/__init__.py.")
    private = os.environ.get(KEY_VARIABLE, '').strip()
    if not private:
        raise SystemExit(f"{KEY_VARIABLE} is not set, so the release cannot be signed.")
    manifest = sign_manifest(private, version, _sha256_file(exe))
    try:
        verify_manifest(manifest, public_key)
    except UpdateError:
        raise SystemExit(f"{KEY_VARIABLE} does not match PUBLIC_KEY in src/updater.py.") from None
    with open(exe + '.sig', 'w', encoding='ascii') as f:
        json.dump(manifest, f, indent=1)
        f.write('\n')
    print(f"Signed {os.path.basename(exe)} {version}")


def verify(exe, public_key=None):
    with open(exe + '.sig', encoding='ascii') as f:
        version, sha256 = verify_manifest(json.load(f), public_key)
    if _sha256_file(exe) != sha256:
        raise SystemExit("The signature verifies, but not for this file.")
    print(f"{os.path.basename(exe)} {version}: signature good")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('keygen').add_argument('private_key_file')
    signer = sub.add_parser('sign')
    signer.add_argument('exe')
    signer.add_argument('--tag')
    sub.add_parser('verify').add_argument('exe')
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            keygen(args.private_key_file)
        elif args.command == 'sign':
            sign(args.exe, args.tag)
        else:
            verify(args.exe)
    except UpdateError as e:
        raise SystemExit(str(e)) from None


if __name__ == '__main__':
    main()
