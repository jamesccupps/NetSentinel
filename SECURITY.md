# Security Policy

NetSentinel captures network traffic, extracts credentials from unencrypted
protocols, and runs with Administrator/root privileges. Bugs in it have real
consequences, so please report them privately rather than opening a public issue.

## Reporting a vulnerability

Use GitHub's private reporting:
**[Report a vulnerability](https://github.com/jamesccupps/NetSentinel/security/advisories/new)**

Please include the affected version, what an attacker would need (local user,
same LAN, ability to send traffic), reproduction steps, and the impact you
believe it has. A proof of concept helps but is not required.

Expect an acknowledgement within a week. Please give a fix a reasonable window
before publishing details.

## Scope

In scope:

- Privilege escalation from an unprivileged local user (NetSentinel runs elevated)
- Remote code execution or crashes triggered by crafted network traffic
- Disclosure of captured credentials or the forensics vault to unintended parties
- Detection bypasses that are reachable by an attacker on the monitored network

Out of scope:

- False positives and false negatives in detection rules — open a normal issue
- The default machine-derived vault key. This is documented, intentional, and
  explicitly **not** a confidentiality boundary; see below.

## What the forensics vault does and does not protect

`~/.netsentinel/data/forensics/credentials.enc` is encrypted with Fernet
(AES-128-CBC + HMAC-SHA256), not AES-256.

By default the key is derived from hostname + username. That ties the file to
one machine but is **not secret** — anyone holding the file can usually
reproduce it. It protects against casual inspection of a copied file and
nothing more.

For actual confidentiality, set a passphrase:

```json
{"forensics": {"vault_passphrase": "..."}}
```

which switches key derivation to scrypt over a random salt. Without the
passphrase the vault cannot be opened.

Since v1.5.0 only **masked** credential values are stored by default. Full
plaintext secrets are retained only if you set
`forensics.store_raw_credentials` to `true`.

## What the dashboard's session does and does not protect

The browser dashboard (`http://127.0.0.1:8737/`) opens only through a link
NetSentinel itself opens: **Open in Browser**, the tray's **Open dashboard**, or
the link `--headless` prints to its console. The link sets an `HttpOnly`,
`SameSite=Strict` cookie for that browser, for the life of that NetSentinel
process. Without it every page and API route except `/health` and
`/api/metrics` (counters only) is refused, and every control also needs a token
the page reads with its session.

That keeps other programs on the computer, of any account and without
Administrator rights, from reading alerts and captured findings or using the
controls of a process that runs elevated, and keeps web pages from driving it.
It does not protect against a program that can already read your browser's
cookies or act as Administrator. Since v1.17.0; before, the page carried the
token and any local program could fetch it.

## Operating NetSentinel safely

- It must run elevated to capture packets. Treat it as privileged software.
- Keep `NetSentinel.exe` in a folder only administrators can write, such as
  Program Files. NetSentinel holds its own exe while it runs and starts an
  update only as it was checked, but in a folder your ordinary programs can
  write (Downloads, a Scoop folder in your profile), one of them could
  replace the exe before you next start it.
- `~/.netsentinel/` holds captured credentials, alert history and your
  VirusTotal API key. It is created `0700` with files `0600` where the platform
  supports it; on Windows, check the ACLs yourself.
- Exported PCAPs contain raw traffic, including anything sent in cleartext.
  Handle them like the sensitive artifacts they are.
- Capturing traffic you are not authorised to capture may be illegal. That is
  your responsibility, not the tool's.
