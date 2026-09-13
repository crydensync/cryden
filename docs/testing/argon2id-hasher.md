# Manual test guide — Argon2id hasher

bcrypt is not broken, and this does not replace it. What it cannot do is
resist an attacker with a GPU as well as a memory-hard function can: its
working set is about 4 KiB, small enough to fit thousands of parallel
instances on one card. Argon2id's is whatever you configure — 64 MiB by
default here — which is the whole point.

`security.Argon2idHasher` is a **second implementation of the same
`security.Hasher` interface**, not a new hook. `Hash` and `Compare` are
the whole surface, and nothing in `auth/` can tell which one it holds.

The real question this feature had to answer is not "how do we hash with
Argon2id" — it is **"what happens to the bcrypt hashes already in the
users table?"** The answer is that nothing happens to them, and nothing
needs to: every hash names its own algorithm and carries its own
parameters, so verification reads what to do out of the hash in front of
it. There is no algorithm column, no backfill job, and no window during
which some accounts cannot log in.

The fastest full check is the smoke test:

```
go run ./cmd/smoketest/argon2id-hasher
```

120 checks over twelve sections, no database and no configuration
required. It covers the negative half too: tampered and unreadable stored
hashes, a wrong password, and a users table that refuses the rewrite.

## Setup

Switching is one field:

```go
hasher, err := security.NewArgon2idHasher(security.DefaultArgon2idParams)
if err != nil {
	return err
}

engine, err := cryden.New(cryden.Config{
	JWTSecret: os.Getenv("JWT_SECRET"),
	Users:     users,
	Sessions:  sessions,
	Audit:     audit,

	Hasher: hasher, // ← the only change
})
```

`Config.BcryptCost` is ignored once `Hasher` is set — it is the default
hasher's constructor argument, and a hasher you built already carries its
own cost. Leaving `Hasher` nil keeps the previous behaviour exactly:
bcrypt at `BcryptCost`.

Passing the zero value `security.Argon2idParams{}` is the same as passing
`DefaultArgon2idParams`. Set even one field and the struct is treated as
a real configuration and validated as-is — the same rule
`PasswordPolicy` and `AnomalyThresholds` follow.

### Parameters

| Field | Default | Meaning | Floor enforced |
| --- | --- | --- | --- |
| `Memory` | `65536` (64 MiB) | KiB of memory per hash — the cost an attacker cannot parallelize away | `8 × Parallelism`, max 4 GiB |
| `Iterations` | `3` | Passes over that memory | `1` |
| `Parallelism` | `4` | Lanes, i.e. threads one hash may use | `1` |
| `SaltLength` | `16` | Bytes of random salt per hash | `8` |
| `KeyLength` | `32` | Bytes of derived key stored | `16` |

The defaults are RFC 9106's second recommended option (64 MiB, t=3,
p=4). OWASP's floor is lower — 19 MiB, t=2, p=1 — and is a reasonable
target if 64 MiB per concurrent login is more than your instances have
to spare. **Tune against your own hardware and your own login rate:**
memory is per in-flight hash, so 64 MiB and 50 concurrent logins is
3.2 GiB of transient allocation.

Anything below the floors above is rejected with
`security.ErrInvalidArgon2idParams` at construction time rather than
silently rounded. Two of them are not stylistic: `x/crypto/argon2`
*panics* on `Iterations` or `Parallelism` of zero, so a zero there would
otherwise take the process down on the first login.

## 1. Nothing changes for a new deployment

Sign up and log in with `Hasher` unset. Read the stored hash:

```sql
SELECT password_hash FROM users WHERE email = 'raymondproguy@dev.com';
```

It starts with `$2a$` or `$2b$` — bcrypt, exactly as before. This
feature is opt-in in the strict sense: unset, it is not in the code path
at all beyond a dispatch that recognises bcrypt and hands over to it.

## 2. A switch migrates accounts as they log in

The interesting scenario, and the one worth doing by hand:

1. Run your app with `Hasher` unset. Sign up as
   `raymondproguy@dev.com` / `Tr0ubl3-Fr33!2026`.
2. Confirm the stored hash starts with `$2a$` — that is what
   `x/crypto/bcrypt` writes.
3. Stop the app. Set `Hasher` to an Argon2id hasher. Start it again.
4. Log in with the same password. It works — no reset, no error, nothing
   the user sees.
5. Read the stored hash again. It now starts with
   `$argon2id$v=19$m=65536,t=3,p=4$`.

That last step is the migration. It happens on the one call where the
plaintext password and the stored hash are both in hand, which is the
only moment a rewrite is possible at all.

Log in a second time and the hash does not change again — it is already
current, so there is no write and no audit event.

## 3. Watching the migration drain

Each rewrite records a `store.EventPasswordHashUpgraded` audit event
carrying which algorithm it came from and went to:

```sql
SELECT created_at, user_id, metadata
FROM audit_events
WHERE type = 'password_hash_upgraded'
ORDER BY created_at DESC
LIMIT 20;
```

`metadata` reads `{"from": "bcrypt", "to": "argon2id"}`. Neither the
password nor either hash is ever recorded.

Counting these against your active-user count is how you know how far
along the migration is. It will never reach 100%: accounts that never log
in again are never rewritten, and that is correct — their bcrypt hashes
keep working indefinitely, and nothing can rewrite one without seeing the
password.

## 4. Raising bcrypt's cost is the same mechanism

You do not have to change algorithm to use this. Sign up at
`BcryptCost: 10`, then restart with `BcryptCost: 12` and log in. The
stored hash is rewritten at cost 12, and the same audit event is recorded
with `from` and `to` both `bcrypt`. Check the cost in the hash itself —
it is the number right after the `$2a$`.

A hash **above** the configured cost is left alone. Rolling a cost
increase back should not walk every stored hash back down with it.

## 5. Rolling back works

Set `Hasher` back to nil (or to a bcrypt hasher) and log in with an
account that was already migrated to Argon2id. It still works: dispatch
is symmetric, so a bcrypt-configured engine verifies Argon2id hashes just
as happily as the reverse.

That engine will then consider the Argon2id hash out of date and rewrite
it as bcrypt on that login. If you are testing a rollback and want to
avoid churning hashes in both directions, expect this.

## 6. Wrong passwords, tampered hashes

None of these may ever verify, and none may panic:

- A wrong password on a migrated account → `ErrInvalidCredentials`, and
  the stored hash is **not** rewritten. This one matters: if a failed
  login triggered a rehash, every guess in a spray would cost the
  victim's account a full Argon2id computation and a database write.
- A stored hash edited by hand — change one character of the salt or key
  segment → `ErrInvalidCredentials`.
- A stored hash with `t=0`, `p=0`, or an enormous `m=` → rejected as
  unreadable, not executed. Without the guard, the first two panic inside
  `x/crypto` and the third tries to allocate terabytes.
- A hash from another library (`$argon2i$`, `$scrypt$`, PBKDF2) →
  unreadable. Only `$argon2id$` and the four bcrypt prefixes are claimed;
  anything else is handed to whatever hasher you configured, which is the
  only thing that could have written it.

## 7. A custom hasher still works

If you have your own `security.Hasher`, it keeps working untouched, and
its hashes are never rewritten: the upgrade is driven by an optional
`security.Rehasher` interface (`NeedsRehash(hash string) bool`) that your
implementation does not have to satisfy. Not implementing it means "never
upgrade," which is the only safe default — there is no way to guess what
your implementation would consider out of date.

Implement `Rehasher` if you want in: return `true` for hashes you would
rather have rewritten, and a successful login will rewrite them.

## Postgres

Nothing to run. No schema change, no migration, no new column — the
`password_hash` column holds a longer string than it used to and that is
the entire storage impact. Argon2id hashes at the default parameters are
about 100 characters; bcrypt's are 60. If your column is `varchar(60)`
rather than `text`, widen it before switching, or the first rewrite will
fail (the login will still succeed — see `## Known limits`).

## Known limits

- **Login timing tells you which algorithm an account uses.** An
  Argon2id verification at 64 MiB takes measurably longer than bcrypt at
  cost 10. During a migration, an attacker who can time responses can
  tell migrated accounts from unmigrated ones. This leaks nothing about
  any password and no way to attack either kind faster; it is noted
  because it is real and there is no way to hide it while both formats
  are in use.
- **The rewrite is opportunistic, not guaranteed.** If the store rejects
  the write — read-only replica, a column too narrow, a permissions
  problem — the login still succeeds and the hash stays as it was. The
  failure is logged at error level (`login: password rehash store
  error`) and no audit event is recorded, so the event count never
  overstates how far the migration got. Watch that log line: a migration
  that is not progressing looks identical to one nobody is logging in
  for.
- **Accounts that never log in are never migrated.** There is no
  server-side way around this — rewriting a hash requires the plaintext
  password. If you need every row converted, the only options are forcing
  a password reset or accepting bcrypt indefinitely for dormant accounts.
- **Parallelism is not part of the "out of date" test.** It is a
  throughput knob tied to your hardware, not a strength one; including it
  would rewrite every stored hash the first time the service moved to a
  machine with a different core count.
- **The smoke test uses deliberately tiny parameters** (64 KiB, t=1) so
  it runs in under a second. It proves which algorithm was used and that
  dispatch is correct — never that your configured parameters are strong
  enough for your threat model.
