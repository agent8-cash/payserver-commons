# Pull-subscription allowance events — shared-type note

Status: design only, companion to the main design document in `ethpayserver`
(`docs/pull-subscription-design.md`). No contract is deployed and no code
here is implemented by this note; it records only the shared-type impact of
that design on this repository.

## What this repo needs to add

`ethpayserver`'s design for capped-allowance pull subscriptions (direct
ERC-20 `transferFrom` by the merchant's own key, no contract of ours in the
payment path — see the main document for the full reasoning) relies on the
chain monitor observing ERC-20 `Approval` events and allowance reads, the
same way it already observes `Transfer` events for payment detection.

The wire protocol between a chain monitor and its consumer lives here, in
`payserver-chain-proto/src/event.rs::ChainEventKind`. Today it has no variant
for an allowance observation — `PaymentDetected` / `PaymentConfirmed` are
shaped around a payment amount landing at an address, not an approval amount
being granted or revoked for a (owner, spender, token) tuple. Overloading
`PaymentDetected` for this would conflate two different things a consumer
needs to tell apart.

**Proposed addition** (not yet implemented), following the existing
variants' shape in the same enum:

```rust
AllowanceObserved {
    owner: ChainText,
    spender: ChainText,
    asset: ChainText,           // the ERC-20 token address; never empty, unlike payment's optional asset
    amount: Amount,              // the allowance() value at observation time, raw units
    payment: Option<PaymentRef>, // the Approval event's tx, when this came from an event rather than a poll
},
```

A zero `amount` is how a revocation surfaces to the consumer — no separate
`Revoked` variant is needed, because `approve(spender, 0)` is just another
value of the same observation, and `ethpayserver`'s `pull_allowance_state`
flags it as a revocation once the amount is below what the next pull needs.

## Why this belongs here and not duplicated per-chain

`ChainId` (`types/src/types/chain.rs`) already carries the CAIP-2 namespace
that tells a consumer whether a chain can produce this event at all
(`is_evm()` — `eip155` only; see the main document's chain-coverage table).
This repo doesn't need a new enum for "which chains support allowances" —
that's already answered by the existing namespace check, not a new shared
type. The only genuinely new shared surface is the event variant above.

## Pin impact

Nothing here ships to `ethpayserver` on its own — this repository is pinned
by revision, and merging a variant here changes nothing downstream until
`ethpayserver` bumps its pin and implements the producer/consumer side. If
and when the `AllowanceObserved` variant above is actually implemented (a
separate, future change — this note is design only), expect two PRs: one
here, one in `ethpayserver` bumping the pin, per the usual three-step dance.

## Non-goals

Same as the main document: no contract deployment, no approval flow merged,
no key or signer touched. This note does not implement the variant above; it
records the shape so the main design doesn't have to guess at what commons
would need to add.
