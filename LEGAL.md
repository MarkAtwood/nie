# nie relay — Legal Policy

## What data we hold

The nie relay stores the minimum possible information consistent with its
function as an encrypted message relay:

| Field | Description |
|-------|-------------|
| `pub_id` | `hex(SHA-256(ed25519_verifying_key))` — a one-way hash of the public key. We cannot reverse it to recover the key, and the key cannot be used to identify a person. |
| `first_seen` | Unix timestamp of the account's first successful authentication to this relay instance. |
| `subscription_expires` | Subscription expiry timestamp, if a subscription payment was received. |

We do **not** store:

- IP addresses or network identifiers
- Message content (all messages are end-to-end encrypted; the relay routes
  opaque ciphertext and cannot decrypt it)
- Payment addresses or transaction details beyond the merchant invoice used to
  accept subscription payment
- Nicknames or display names beyond what is cached in memory for connected
  sessions (not persisted to disk)
- Any government-issued identifier, email address, phone number, or other PII

## Legal demand policy

### What we will produce

If we receive a valid legal demand compelling us to produce records, we can
produce only the three fields listed above (pub_id, first_seen,
subscription_expires) for accounts that exist in our database.

We cannot produce IP addresses, message content, or decryption keys because
we do not have them.

### Research fee (18 USC 2706)

For demands issued to a US-based relay operator: pursuant to 18 U.S.C. § 2706,
we will bill the requesting government entity for the reasonable cost of
producing records before complying with any demand that does not explicitly
waive the fee. The minimum fee is $1,000 per demand. This policy is posted
publicly and applies uniformly regardless of the requesting agency.

### Transparency

Every legal demand we receive — including demands we challenge or refuse — will
be logged in our public transparency log at `GET /transparency` on this relay.
We will not suppress entries for demands that were successfully resisted.

Log entries include: sequential ID, requesting entity name, demand type
(subpoena / court order / preservation), date received, current status
(responded / pending / challenged), and a link to the redacted response
document where permitted.

### Challenge policy

We will challenge demands that:

- Lack proper legal authority for the jurisdiction
- Seek data we do not hold (e.g., IP addresses, message content)
- Are accompanied by a gag order preventing transparency log publication
  (we will seek to have such orders lifted or narrowed)
- Are issued by entities without jurisdiction over the relay operator

## Warrant canary

This file was last reviewed on: 2026-04-22.

We have not received any secret demands, gag orders, national security letters,
or court orders that would prevent us from publishing information about legal
demands as of the date above. If this section is removed or not updated within
90 days, treat it as a canary absence.
