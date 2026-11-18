import argparse
import base64
import sys
from typing import Union

import pyrage
import pyrage.ssh
import pyrage.x25519

Recipient = Union[pyrage.ssh.Recipient, pyrage.x25519.Recipient]
Identity = Union[pyrage.ssh.Identity, pyrage.x25519.Identity]


def load_recipients(keyfile: str) -> list[Recipient]:
    recipients: list[Recipient] = []
    with open(keyfile) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if line.startswith("age1"):
                    recipients.append(pyrage.x25519.Recipient.from_str(line.split()[0]))
                elif line.startswith("ssh-"):
                    recipients.append(pyrage.ssh.Recipient.from_str(line))
                else:
                    raise ValueError(f"unrecognized key format: {line!r}")
            except Exception as e:
                sys.exit(f"{keyfile}:{lineno}: failed to parse key: {e}")
    if not recipients:
        sys.exit(f"{keyfile}: no recipient keys found")
    return recipients


def load_identities(keyfile: str) -> list[Identity]:
    with open(keyfile) as f:
        text = f.read()

    identities: list[Identity] = []
    if "AGE-SECRET-KEY-" in text:
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                identities.append(pyrage.x25519.Identity.from_str(line))
            except Exception as e:
                sys.exit(f"{keyfile}:{lineno}: failed to parse identity: {e}")
    elif text.startswith("-----BEGIN"):
        try:
            identities.append(pyrage.ssh.Identity.from_buffer(text.encode()))
        except Exception as e:
            sys.exit(f"{keyfile}: failed to parse SSH private key: {e}")
    else:
        sys.exit(f"{keyfile}: unrecognized identity file format")

    if not identities:
        sys.exit(f"{keyfile}: no identity keys found")
    return identities


def do_encrypt(args: argparse.Namespace) -> None:
    recipients = load_recipients(args.keyfile)

    with open(args.message, "rb") as f:
        plaintext = f.read()

    ciphertext: bytes = pyrage.encrypt(plaintext, recipients, armored=args.armor)
    encoded: bytes = base64.b64encode(ciphertext)

    output: str = args.output or (args.message + ".b64")
    with open(output, "wb") as f:
        f.write(encoded)

    print(f"Encrypted {args.message} -> {output} ({len(recipients)} recipient(s))")


def do_decrypt(args: argparse.Namespace) -> None:
    identities = load_identities(args.keyfile)

    with open(args.message, "rb") as f:
        encoded = f.read()

    try:
        ciphertext: bytes = base64.b64decode(encoded)
    except Exception as e:
        sys.exit(f"base64 decoding failed: {e}")

    try:
        plaintext: bytes = pyrage.decrypt(ciphertext, identities)
    except Exception as e:
        sys.exit(f"decryption failed: {e}")

    if args.output:
        with open(args.output, "wb") as f:
            f.write(plaintext)
        print(f"Decrypted {args.message} -> {args.output}")
    else:
        sys.stdout.buffer.write(plaintext)


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt a message with pyrage.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a message for one or more recipients")
    enc.add_argument("--keyfile", required=True, help="File with one SSH or age public key per line")
    enc.add_argument("--message", required=True, help="File containing the plaintext message")
    enc.add_argument("-o", "--output", help="Output file (default: <message>.b64)")
    enc.add_argument("--armor", action="store_true", help="Write ASCII-armored output")
    enc.set_defaults(func=do_encrypt)

    dec = subparsers.add_parser("decrypt", help="Decrypt a message with one or more identities")
    dec.add_argument("--keyfile", required=True, help="Age identity file, or a single SSH private key file")
    dec.add_argument("--message", required=True, help="File containing the encrypted message")
    dec.add_argument("-o", "--output", help="Output file (default: print plaintext to stdout)")
    dec.set_defaults(func=do_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
