# types

Common types and traits for the PayServer ecosystem.

## Purpose

This crate provides data types shared across PayServer implementations
(ethpayserver and any future payserver on another chain family). It defines:

- **ChainId** - CAIP-2 chain identity (`eip155:1`, `tron:728126428`, ...), open by
  construction so a chain can be added without touching this crate — see
  `types::ChainId` below
- **Data types** - `InvoiceData`, `PaymentData`, `TokenData`
- **Repository traits** - Database abstraction layer (around twenty traits;
  `InvoiceRepository`, `PaymentRepository` and `TokenRepository` are three of them)

## Modules

| Module | Description |
|--------|-------------|
| `types` | Core types: `ChainId`, `InvoiceId`, `InvoiceStatus`, `PaymentEvent`, `UserId` |
| `store` | Multi-tenant types: `Store`, `StoreId`, `StoreInfo` |
| `traits` | `InvoiceData`, `PaymentData`, `InvoiceQuery` |
| `repositories` | Database traits — see `src/repositories/` for the full list |
| `currency` | Currency/amount handling |
| `error` | `PayServerError` and `PayServerResult` |

## Store Types

The `store` module provides multi-tenant store support:

```rust
use types::{Store, StoreId, StoreInfo, UserId};

// Create a store
let owner_id = UserId::new();
let store = Store::new("My Shop", owner_id)
    .with_website("https://myshop.com");

// StoreInfo for API responses (excludes owner_id)
let info: StoreInfo = (&store).into();
```

| Type | Description |
|------|-------------|
| `StoreId` | UUID wrapper for store identification |
| `Store` | Full store entity with owner_id |
| `StoreInfo` | Sanitized store data for API responses |
| `UserId` | UUID wrapper for user identification |

## Repository Pattern

Each domain has Reader/Writer/Repository traits:

```rust
// Read-only access for API queries
fn list_invoices(reader: &impl InvoiceReader) { ... }

// Write access for processing
fn create_invoice(writer: &impl InvoiceWriter) { ... }

// Full access
fn process_payment(repo: &impl InvoiceRepository) { ... }
```

## Chain Identity

Chains are identified by [CAIP-2](https://standards.chainagnostic.org/CAIPs/caip-2)
string, not a closed enum — the old `Network` enum required editing this crate
and cutting a release for every new chain, which meant a plugin could never add
one. `types::ChainId` covers five namespaces today: `eip155` (Ethereum and other
EVM chains), `tron`, `solana`, `monero`, `bip122` (Bitcoin). Which chains a given
payserver actually supports is data (`chain_configs`), not something this crate
enumerates — see `types::chain` for the format and worked examples.

```rust
use types::ChainId;

let ethereum = ChainId::evm(1);           // eip155:1
let tron_mainnet = ChainId::parse("tron:728126428")?;
```

## Features

| Feature | Description |
|---------|-------------|
| `openapi` | Adds `utoipa::ToSchema` derives for OpenAPI documentation |
